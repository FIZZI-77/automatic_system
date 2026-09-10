package retentionworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const (
	defaultArchiveAfter    = 24 * time.Hour
	defaultPurgeAfter      = 30 * 24 * time.Hour
	defaultArchiveInterval = 5 * time.Minute
	defaultPurgeInterval   = time.Hour
	defaultBatchSize       = 100
	retentionLockNamespace = 0x5245544e
)

type Config struct {
	ArchiveAfter    time.Duration
	PurgeAfter      time.Duration
	ArchiveInterval time.Duration
	PurgeInterval   time.Duration
	BatchSize       int
}

type Worker struct {
	db     *pgxpool.Pool
	cfg    Config
	logger *zap.Logger
}

func New(db *pgxpool.Pool, cfg Config, logger *zap.Logger) (*Worker, error) {
	if db == nil {
		return nil, errors.New("retention worker: database is required")
	}
	if cfg.ArchiveAfter <= 0 {
		cfg.ArchiveAfter = defaultArchiveAfter
	}
	if cfg.PurgeAfter <= 0 {
		cfg.PurgeAfter = defaultPurgeAfter
	}
	if cfg.ArchiveInterval <= 0 {
		cfg.ArchiveInterval = defaultArchiveInterval
	}
	if cfg.PurgeInterval <= 0 {
		cfg.PurgeInterval = defaultPurgeInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.PurgeAfter <= cfg.ArchiveAfter {
		return nil, errors.New("retention worker: purge age must be greater than archive age")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Worker{db: db, cfg: cfg, logger: logger}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("ticket retention workers started",
		zap.Duration("archive_after", w.cfg.ArchiveAfter),
		zap.Duration("purge_after", w.cfg.PurgeAfter),
		zap.Duration("archive_interval", w.cfg.ArchiveInterval),
		zap.Duration("purge_interval", w.cfg.PurgeInterval),
	)
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); w.runArchiveLoop(ctx) }()
	go func() { defer group.Done(); w.runPurgeLoop(ctx) }()
	group.Wait()
	return nil
}

func (w *Worker) runArchiveLoop(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.ArchiveInterval)
	defer ticker.Stop()
	for {
		if count, err := w.ArchiveOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("ticket archival cycle failed", zap.Error(err))
		} else if count > 0 {
			w.logger.Info("tickets archived", zap.Int("count", count))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) runPurgeLoop(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.PurgeInterval)
	defer ticker.Stop()
	for {
		if count, err := w.PurgeOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("ticket purge cycle failed", zap.Error(err))
		} else if count > 0 {
			w.logger.Info("archived tickets purged", zap.Int("count", count))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type archiveCandidate struct {
	id     uuid.UUID
	status string
}

func (w *Worker) ArchiveOnce(ctx context.Context) (int, error) {
	tx, err := w.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin archive transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	rows, err := tx.Query(ctx, `
		SELECT id, status
		FROM tickets
		WHERE status IN ('DONE', 'CANCELED')
		  AND COALESCE(completed_at, canceled_at, updated_at) <= $1
		ORDER BY COALESCE(completed_at, canceled_at, updated_at)
		LIMIT $2`, time.Now().UTC().Add(-w.cfg.ArchiveAfter), w.cfg.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("select archive candidates: %w", err)
	}
	candidates := make([]archiveCandidate, 0, w.cfg.BatchSize)
	for rows.Next() {
		var candidate archiveCandidate
		if err = rows.Scan(&candidate.id, &candidate.status); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan archive candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate archive candidates: %w", err)
	}
	rows.Close()

	now := time.Now().UTC()
	archived := 0
	for _, candidate := range candidates {
		if err = lockTicket(ctx, tx, candidate.id); err != nil {
			return 0, fmt.Errorf("lock archive candidate %s: %w", candidate.id, err)
		}
		result, updateErr := tx.Exec(ctx, `
			UPDATE tickets
			SET status='ARCHIVED', archived_at=$3, updated_at=$3
			WHERE id=$1 AND status=$2
			  AND COALESCE(completed_at, canceled_at, updated_at) <= $4`,
			candidate.id,
			candidate.status,
			now,
			now.Add(-w.cfg.ArchiveAfter),
		)
		if updateErr != nil {
			return 0, fmt.Errorf("archive ticket %s: %w", candidate.id, updateErr)
		}
		if result.RowsAffected() == 0 {
			continue
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ticket_status_history(id,department_id,ticket_id,old_status,new_status,comment,created_at) SELECT $1,department_id,id,$3,'ARCHIVED',$4,$5 FROM tickets WHERE id=$2`, uuid.New(), candidate.id, candidate.status, "Archived automatically after 24 hours in terminal status", now); err != nil {
			return 0, fmt.Errorf("record archive history %s: %w", candidate.id, err)
		}
		if err = insertRetentionEvent(ctx, tx, candidate.id, "ticket.archived", now); err != nil {
			return 0, err
		}
		archived++
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit archive transaction: %w", err)
	}
	return archived, nil
}

func (w *Worker) PurgeOnce(ctx context.Context) (int, error) {
	tx, err := w.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin purge transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	rows, err := tx.Query(ctx, `
		SELECT id
		FROM tickets
		WHERE status='ARCHIVED' AND archived_at <= $1
		ORDER BY archived_at
		LIMIT $2`, time.Now().UTC().Add(-w.cfg.PurgeAfter), w.cfg.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("select purge candidates: %w", err)
	}
	ids := make([]uuid.UUID, 0, w.cfg.BatchSize)
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan purge candidate: %w", err)
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate purge candidates: %w", err)
	}
	rows.Close()

	now := time.Now().UTC()
	purged := 0
	for _, id := range ids {
		if err = lockTicket(ctx, tx, id); err != nil {
			return 0, fmt.Errorf("lock purge candidate %s: %w", id, err)
		}
		result, deleteErr := tx.Exec(ctx, `DELETE FROM tickets WHERE id=$1 AND status='ARCHIVED' AND archived_at <= $2`, id, now.Add(-w.cfg.PurgeAfter))
		if deleteErr != nil {
			return 0, fmt.Errorf("purge ticket %s: %w", id, deleteErr)
		}
		if result.RowsAffected() == 0 {
			continue
		}
		if err = insertRetentionEvent(ctx, tx, id, "ticket.purged", now); err != nil {
			return 0, err
		}
		purged++
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit purge transaction: %w", err)
	}
	return purged, nil
}

func lockTicket(ctx context.Context, tx pgx.Tx, ticketID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, $2))`, ticketID, retentionLockNamespace)
	return err
}

func insertRetentionEvent(ctx context.Context, tx pgx.Tx, ticketID uuid.UUID, eventType string, occurredAt time.Time) error {
	payload, err := json.Marshal(map[string]any{"event_id": uuid.NewString(), "event_type": eventType, "ticket_id": ticketID.String(), "occurred_at": occurredAt})
	if err != nil {
		return fmt.Errorf("marshal %s event: %w", eventType, err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,created_at) VALUES($1,'ticket',$2,$3,$4,'PENDING',$5)`, uuid.New(), ticketID, eventType, payload, occurredAt); err != nil {
		return fmt.Errorf("insert %s event for ticket %s: %w", eventType, ticketID, err)
	}
	return nil
}
