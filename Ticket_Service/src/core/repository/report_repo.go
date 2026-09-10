package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"ticket/models"
)

type ReportRepository struct{ repo *Repository }

const completionAttemptTimeout = 10 * time.Minute

func NewReportRepository(repo *Repository) *ReportRepository { return &ReportRepository{repo: repo} }

func (r *ReportRepository) Create(ctx context.Context, in *models.CreateWorkReportInput) (report *models.WorkReport, err error) {
	tx, err := r.repo.writePool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()
	if in.IdempotencyKey != "" {
		existing := new(models.WorkReport)
		err = tx.QueryRow(
			ctx,
			findReportByIdempotencyKeyQuery,
			in.TicketID,
			in.AuthorUserID,
			in.IdempotencyKey,
		).Scan(
			&existing.ID,
			&existing.TicketID,
			&existing.AuthorUserID,
			&existing.Description,
			&existing.CreatedAt,
			&existing.UpdatedAt,
			&existing.CompletionStatus,
			&existing.CompletionFileID,
			&existing.CompletionError,
		)
		if err == nil {
			rows, queryErr := tx.Query(ctx, `SELECT file_id FROM ticket_report_files WHERE report_id=$1 ORDER BY created_at`, existing.ID)
			if queryErr != nil {
				return nil, queryErr
			}
			for rows.Next() {
				var fileID uuid.UUID
				if queryErr = rows.Scan(&fileID); queryErr != nil {
					rows.Close()
					return nil, queryErr
				}
				existing.FileIDs = append(existing.FileIDs, fileID)
			}
			queryErr = rows.Err()
			rows.Close()
			if queryErr != nil {
				return nil, queryErr
			}
			return existing, tx.Commit(ctx)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	report = &models.WorkReport{
		ID:           uuid.New(),
		TicketID:     in.TicketID,
		AuthorUserID: in.AuthorUserID,
		Description:  in.Description,
		FileIDs:      in.FileIDs,
	}
	err = tx.QueryRow(
		ctx,
		insertReportQuery,
		report.ID,
		report.TicketID,
		report.AuthorUserID,
		report.Description,
		in.IdempotencyKey,
	).Scan(&report.CreatedAt, &report.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create report: %w", err)
	}
	for _, id := range in.FileIDs {
		if _, err = tx.Exec(ctx, `INSERT INTO ticket_report_files(department_id,report_id,file_id) SELECT department_id,id,$2 FROM ticket_reports WHERE id=$1`, report.ID, id); err != nil {
			return nil, fmt.Errorf("attach report file: %w", err)
		}
	}
	eventType := "ticket.report.created"
	payloadValue := any(report)
	if in.Completion != nil {
		if _, err = tx.Exec(ctx, `UPDATE ticket_reports SET completion_status='PENDING',completion_attempts=1,completion_deadline_at=now()+make_interval(secs => $2),completion_updated_at=now() WHERE id=$1`, report.ID, completionAttemptTimeout.Seconds()); err != nil {
			return nil, fmt.Errorf("mark completion pending: %w", err)
		}
		report.CompletionStatus = "PENDING"
		eventType = "ticket.completion_report.requested.v1"
		var title, address string
		if err = tx.QueryRow(ctx, `SELECT title,address FROM tickets WHERE id=$1`, report.TicketID).Scan(&title, &address); err != nil {
			return nil, fmt.Errorf("read completion ticket snapshot: %w", err)
		}
		payloadValue = map[string]any{
			"work_report_id": report.ID,
			"requested_by":   in.Completion.RequestedBy,
			"actor_roles":    in.Completion.ActorRoles,
			"ticket": map[string]string{
				"id": report.TicketID.String(), "title": title, "address": address,
			},
			"brigade":         in.Completion.Brigade,
			"opened_by":       in.Completion.OpenedBy,
			"description":     report.Description,
			"file_ids":        report.FileIDs,
			"idempotency_key": in.IdempotencyKey,
		}
	}
	payload, err := json.Marshal(payloadValue)
	if err != nil {
		return nil, fmt.Errorf("marshal report event: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload) VALUES($1,'ticket_report',$2,$3,$4)`, uuid.New(), report.ID, eventType, payload)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return report, nil
}

func (r *ReportRepository) List(ctx context.Context, ticketID uuid.UUID) ([]*models.WorkReport, error) {
	rows, err := r.repo.readPool.Query(ctx, listReportsQuery, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*models.WorkReport, 0)
	for rows.Next() {
		x := new(models.WorkReport)
		if err = rows.Scan(&x.ID, &x.TicketID, &x.AuthorUserID, &x.Description, &x.CreatedAt, &x.UpdatedAt, &x.FileIDs, &x.CompletionStatus, &x.CompletionFileID, &x.CompletionError); err != nil {
			return nil, err
		}
		result = append(result, x)
	}
	return result, rows.Err()
}

const findReportByIdempotencyKeyQuery = `
	SELECT
		report.id,
		report.ticket_id,
		report.author_user_id,
		report.description,
		report.created_at,
		report.updated_at,
		report.completion_status,
		report.completion_file_id,
		COALESCE(report.completion_error, '')
	FROM ticket_reports report
	JOIN tickets ticket
		ON ticket.department_id = report.department_id
		AND ticket.id = report.ticket_id
	WHERE ticket.id = $1
		AND report.author_user_id = $2
		AND report.idempotency_key = $3
`

const insertReportQuery = `
	INSERT INTO ticket_reports (
		id,
		department_id,
		ticket_id,
		author_user_id,
		description,
		idempotency_key
	)
	SELECT $1, department_id, id, $3, $4, NULLIF($5, '')
	FROM tickets
	WHERE id = $2
	RETURNING created_at, updated_at
`

const listReportsQuery = `
	SELECT
		report.id,
		report.ticket_id,
		report.author_user_id,
		report.description,
		report.created_at,
		report.updated_at,
		COALESCE(
			array_agg(report_file.file_id)
				FILTER (WHERE report_file.file_id IS NOT NULL),
			'{}'
		),
		report.completion_status,
		report.completion_file_id,
		COALESCE(report.completion_error, '')
	FROM ticket_reports report
	LEFT JOIN ticket_report_files report_file
		ON report_file.department_id = report.department_id
		AND report_file.report_id = report.id
	WHERE report.ticket_id = $1
	GROUP BY report.department_id, report.id
	ORDER BY report.created_at DESC
`
