package repository

import (
	"brigade/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ScheduleRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

func NewScheduleRepo(writePool *pgxpool.Pool, readPool *pgxpool.Pool) *ScheduleRepoStruct {
	return &ScheduleRepoStruct{writePool: writePool, readPool: readPool}
}

func (s *ScheduleRepoStruct) SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error) {
	tx, err := s.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeSchedule: begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const deactivateQuery = `
		UPDATE brigade_schedule
		SET active = false, updated_at = now()
		WHERE brigade_id = $1 AND active = true
	`
	if _, err = tx.Exec(ctx, deactivateQuery, in.BrigadeID); err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeSchedule: deactivate old schedule: %w", err)
	}

	schedule := make([]*models.BrigadeSchedule, 0, len(in.Items))
	for _, item := range in.Items {
		row, err := s.insertBrigadeScheduleItem(ctx, tx, in.BrigadeID, item)
		if err != nil {
			return nil, fmt.Errorf("repo: SetBrigadeSchedule: insert item: %w", err)
		}
		schedule = append(schedule, row)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeScheduleChanged",
		"brigade_id": in.BrigadeID.String(),
		"items":      len(schedule),
	}
	if err = insertOutboxEvent(ctx, tx, "brigade", in.BrigadeID, "BrigadeScheduleChanged", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeSchedule: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeSchedule: commit tx: %w", err)
	}

	return &models.SetBrigadeScheduleResult{Schedule: schedule}, nil
}

func (s *ScheduleRepoStruct) insertBrigadeScheduleItem(ctx context.Context, tx pgx.Tx, brigadeID uuid.UUID, item *models.BrigadeScheduleItem) (*models.BrigadeSchedule, error) {
	timezone := item.Timezone
	if timezone == "" {
		timezone = "Europe/Moscow"
	}

	const query = `
		INSERT INTO brigade_schedule (
			brigade_id,
			day_of_week,
			starts_at,
			ends_at,
			timezone,
			valid_from,
			valid_to
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING
			id,
			brigade_id,
			day_of_week,
			starts_at::text,
			ends_at::text,
			timezone,
			active,
			valid_from,
			valid_to,
			created_at,
			updated_at
	`

	return scanBrigadeSchedule(tx.QueryRow(ctx, query, brigadeID, item.DayOfWeek, item.StartsAt, item.EndsAt, timezone, item.ValidFrom, item.ValidTo))
}

func (s *ScheduleRepoStruct) ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error) {
	whereParts := []string{"brigade_id = $1"}
	args := []any{in.BrigadeID}
	if in.Active != nil {
		args = append(args, *in.Active)
		whereParts = append(whereParts, fmt.Sprintf("active = $%d", len(args)))
	}
	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")

	query := fmt.Sprintf(`
		SELECT
			id,
			brigade_id,
			day_of_week,
			starts_at::text,
			ends_at::text,
			timezone,
			active,
			valid_from,
			valid_to,
			created_at,
			updated_at
		FROM brigade_schedule
		%s
		ORDER BY day_of_week ASC, starts_at ASC
	`, whereSQL)

	rows, err := s.readPool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeSchedule: query: %w", err)
	}
	defer rows.Close()

	schedule := make([]*models.BrigadeSchedule, 0)
	for rows.Next() {
		item, err := scanBrigadeSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("repo: ListBrigadeSchedule: scan: %w", err)
		}
		schedule = append(schedule, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeSchedule: rows: %w", err)
	}
	return &models.ListBrigadeScheduleResult{Schedule: schedule}, nil
}

func scanBrigadeSchedule(row scanner) (*models.BrigadeSchedule, error) {
	var item models.BrigadeSchedule
	var validFrom sql.NullTime
	var validTo sql.NullTime

	err := row.Scan(
		&item.ID,
		&item.BrigadeID,
		&item.DayOfWeek,
		&item.StartsAt,
		&item.EndsAt,
		&item.Timezone,
		&item.Active,
		&validFrom,
		&validTo,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, err
	}
	if validFrom.Valid {
		item.ValidFrom = dateOnlyPtr(validFrom.Time)
	}
	if validTo.Valid {
		item.ValidTo = dateOnlyPtr(validTo.Time)
	}
	return &item, nil
}

func dateOnlyPtr(value time.Time) *time.Time {
	date := time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, value.Location())
	return &date
}
