package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"ticket/models"
)

type ReportRepository struct{ repo *Repository }

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
	report = &models.WorkReport{ID: uuid.New(), TicketID: in.TicketID, AuthorUserID: in.AuthorUserID, Description: in.Description, FileIDs: in.FileIDs}
	err = tx.QueryRow(ctx, `INSERT INTO ticket_reports(id,ticket_id,author_user_id,description) VALUES($1,$2,$3,$4) RETURNING created_at,updated_at`, report.ID, report.TicketID, report.AuthorUserID, report.Description).Scan(&report.CreatedAt, &report.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create report: %w", err)
	}
	for _, id := range in.FileIDs {
		if _, err = tx.Exec(ctx, `INSERT INTO ticket_report_files(report_id,file_id) VALUES($1,$2)`, report.ID, id); err != nil {
			return nil, fmt.Errorf("attach report file: %w", err)
		}
	}
	payload, _ := json.Marshal(report)
	_, err = tx.Exec(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload) VALUES($1,'ticket_report',$2,'ticket.report.created',$3)`, uuid.New(), report.ID, payload)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return report, nil
}

func (r *ReportRepository) List(ctx context.Context, ticketID uuid.UUID) ([]*models.WorkReport, error) {
	rows, err := r.repo.readPool.Query(ctx, `SELECT r.id,r.ticket_id,r.author_user_id,r.description,r.created_at,r.updated_at,COALESCE(array_agg(f.file_id) FILTER(WHERE f.file_id IS NOT NULL),'{}') FROM ticket_reports r LEFT JOIN ticket_report_files f ON f.report_id=r.id WHERE r.ticket_id=$1 GROUP BY r.id ORDER BY r.created_at DESC`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*models.WorkReport, 0)
	for rows.Next() {
		x := new(models.WorkReport)
		if err = rows.Scan(&x.ID, &x.TicketID, &x.AuthorUserID, &x.Description, &x.CreatedAt, &x.UpdatedAt, &x.FileIDs); err != nil {
			return nil, err
		}
		result = append(result, x)
	}
	return result, rows.Err()
}
