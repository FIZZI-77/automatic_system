package repository

import (
	"context"
	"fmt"
	"time"

	"file/models"
	"github.com/google/uuid"
)

type DeletionJob struct {
	FileID    uuid.UUID
	ObjectKey string
}

// GetForDeletion читает primary, включая удалённые записи для безопасного повтора DELETE.
func (r *Repository) GetForDeletion(ctx context.Context, id uuid.UUID) (*models.File, error) {
	return scan(r.writeDB.QueryRow(ctx, `SELECT id,owner_user_id,resource_type,resource_id,name,content_type,size,checksum,object_key,status,created_at,updated_at FROM files WHERE id=$1`, id))
}

// QueueDeletion атомарно скрывает файл и сохраняет повторяемую задачу удаления S3.
// Срок из метаданных позволяет дождаться истечения ранее выданной ссылки PUT.
func (r *Repository) QueueDeletion(ctx context.Context, id uuid.UUID) error {
	_, err := r.writeDB.Exec(ctx, `
		WITH deleted AS (
			UPDATE files SET status='DELETED',deleted_at=now(),updated_at=now()
			WHERE id=$1 AND status<>'DELETED'
			RETURNING id,object_key,COALESCE(upload_expires_at,created_at+interval '7 days') AS upload_expires_at
		)
		INSERT INTO file_deletion_jobs(file_id,object_key,not_before)
		SELECT id,object_key,GREATEST(now(),upload_expires_at) FROM deleted ON CONFLICT (file_id) DO NOTHING`, id)
	if err != nil {
		return fmt.Errorf("queue file deletion: %w", err)
	}
	return nil
}

// ExpireUploads скрывает забытые загрузки и ставит их объекты в очередь очистки.
func (r *Repository) ExpireUploads(ctx context.Context, before time.Time, limit int) error {
	_, err := r.writeDB.Exec(ctx, `
		WITH expired AS (
			SELECT id FROM files WHERE status='PENDING_UPLOAD' AND COALESCE(upload_expires_at,created_at+interval '7 days')<$1
			ORDER BY created_at,id LIMIT $2 FOR UPDATE SKIP LOCKED
		), deleted AS (
			UPDATE files SET status='DELETED',deleted_at=now(),updated_at=now()
			WHERE id IN (SELECT id FROM expired) RETURNING id,object_key
		)
		INSERT INTO file_deletion_jobs(file_id,object_key)
		SELECT id,object_key FROM deleted ON CONFLICT (file_id) DO NOTHING`, before, limit)
	if err != nil {
		return fmt.Errorf("expire pending uploads: %w", err)
	}
	return nil
}

// PendingDeletions возвращает ограниченную порцию готовых задач. Повтор DELETE S3 безопасен.
func (r *Repository) PendingDeletions(ctx context.Context, limit int) ([]DeletionJob, error) {
	rows, err := r.writeDB.Query(ctx, `SELECT file_id,object_key FROM file_deletion_jobs WHERE not_before<=now() ORDER BY not_before,file_id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list file deletions: %w", err)
	}
	defer rows.Close()
	jobs := make([]DeletionJob, 0)
	for rows.Next() {
		var job DeletionJob
		if err := rows.Scan(&job.FileID, &job.ObjectKey); err != nil {
			return nil, fmt.Errorf("scan file deletion: %w", err)
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// CompleteDeletion удаляет задачу только после подтверждения S3.
func (r *Repository) CompleteDeletion(ctx context.Context, id uuid.UUID) error {
	_, err := r.writeDB.Exec(ctx, `DELETE FROM file_deletion_jobs WHERE file_id=$1`, id)
	return err
}

// RetryDeletion сохраняет ошибку и переносит повтор, чтобы одна задача не блокировала очередь.
func (r *Repository) RetryDeletion(ctx context.Context, id uuid.UUID, cause error) error {
	_, err := r.writeDB.Exec(ctx, `UPDATE file_deletion_jobs SET attempts=attempts+1,last_error=$2,not_before=now()+interval '1 minute',updated_at=now() WHERE file_id=$1`, id, cause.Error())
	return err
}
