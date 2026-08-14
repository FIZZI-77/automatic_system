package repository

import (
	"context"
	"errors"
	"fmt"

	"file/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func (r *Repository) Create(ctx context.Context, in models.CreateInput, key string) (*models.File, error) {
	id := uuid.New()
	row := r.db.QueryRow(ctx, `INSERT INTO files(id,owner_user_id,name,content_type,size,checksum,object_key)
		VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,owner_user_id,resource_type,resource_id,name,content_type,size,checksum,object_key,status,created_at,updated_at`,
		id, in.OwnerUserID, in.Name, in.ContentType, in.Size, in.Checksum, key)
	f, err := scan(row)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	return f, nil
}

func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*models.File, error) {
	return scan(r.db.QueryRow(ctx, `SELECT id,owner_user_id,resource_type,resource_id,name,content_type,size,checksum,object_key,status,created_at,updated_at FROM files WHERE id=$1 AND status<>'DELETED'`, id))
}

func (r *Repository) Confirm(ctx context.Context, id uuid.UUID) (*models.File, error) {
	f, err := scan(r.db.QueryRow(ctx, `UPDATE files SET status='UPLOADED',updated_at=now() WHERE id=$1 AND status='PENDING_UPLOAD' RETURNING id,owner_user_id,resource_type,resource_id,name,content_type,size,checksum,object_key,status,created_at,updated_at`, id))
	return f, err
}

func (r *Repository) Quarantine(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE files
		SET status = 'QUARANTINED', updated_at = now()
		WHERE id = $1 AND status = 'PENDING_UPLOAD'`, id)
	return err
}

func (r *Repository) Link(ctx context.Context, id uuid.UUID, in models.LinkInput) (*models.File, error) {
	f, err := scan(r.db.QueryRow(ctx, `UPDATE files SET resource_type=$2,resource_id=$3,status='LINKED',updated_at=now() WHERE id=$1 AND status IN ('UPLOADED','LINKED') RETURNING id,owner_user_id,resource_type,resource_id,name,content_type,size,checksum,object_key,status,created_at,updated_at`, id, in.ResourceType, in.ResourceID))
	return f, err
}

func (r *Repository) List(ctx context.Context, typ string, id uuid.UUID) ([]*models.File, error) {
	rows, err := r.db.Query(ctx, `SELECT id,owner_user_id,resource_type,resource_id,name,content_type,size,checksum,object_key,status,created_at,updated_at FROM files WHERE resource_type=$1 AND resource_id=$2 AND status='LINKED' ORDER BY created_at`, typ, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*models.File, 0)
	for rows.Next() {
		f, err := scan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `UPDATE files SET status='DELETED',deleted_at=now(),updated_at=now() WHERE id=$1 AND status<>'DELETED'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scan(s scanner) (*models.File, error) {
	f := new(models.File)
	err := s.Scan(&f.ID, &f.OwnerUserID, &f.ResourceType, &f.ResourceID, &f.Name, &f.ContentType, &f.Size, &f.Checksum, &f.ObjectKey, &f.Status, &f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, pgx.ErrNoRows
	}
	return f, err
}
