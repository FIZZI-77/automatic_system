package completionsaga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"ticket/pkg/telemetry"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

const (
	defaultAttemptTimeout = 10 * time.Minute
	defaultPollInterval   = 30 * time.Second
	defaultMaxAttempts    = 3
	defaultBatchSize      = 50
)

type Config struct {
	AttemptTimeout time.Duration
	PollInterval   time.Duration
	MaxAttempts    int
	BatchSize      int
}

type Worker struct {
	db     *pgxpool.Pool
	cfg    Config
	logger *zap.Logger
}

type candidate struct {
	id       uuid.UUID
	attempts int
	payload  json.RawMessage
}

type requestPayload struct {
	RequestedBy string   `json:"requested_by"`
	ActorRoles  []string `json:"actor_roles"`
}

const completionLockNamespace = 0x434f4d50

func New(db *pgxpool.Pool, cfg Config, logger *zap.Logger) (*Worker, error) {
	if db == nil {
		return nil, errors.New("completion saga: database is required")
	}
	cfg = withDefaults(cfg)
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Worker{db: db, cfg: cfg, logger: logger}, nil
}

func withDefaults(cfg Config) Config {
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = defaultAttemptTimeout
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	return cfg
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if count, err := w.ProcessExpired(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("completion saga timeout cycle failed", zap.Error(err))
		} else if count > 0 {
			w.logger.Info("completion sagas advanced", zap.Int("count", count))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *Worker) ProcessExpired(ctx context.Context) (processed int, err error) {
	ctx, span := telemetry.Tracer("ticket/completion-saga").Start(ctx, "CompletionSaga.ProcessExpired")
	defer func() { telemetry.End(span, err) }()

	for range w.cfg.BatchSize {
		found, processErr := w.processOne(ctx)
		err = processErr
		if err != nil {
			return processed, err
		}
		if !found {
			return processed, nil
		}
		processed++
	}
	return processed, nil
}

// Resume restarts a failed saga. If a generated file is still present, Resume
// retries compensation first; otherwise it republishes the original request.
func Resume(ctx context.Context, db *pgxpool.Pool, reportID uuid.UUID, attemptTimeout time.Duration) (err error) {
	ctx, span := telemetry.Tracer("ticket/completion-saga").Start(ctx, "CompletionSaga.Resume")
	defer func() { telemetry.End(span, err) }()
	span.SetAttributes(attribute.String("saga.name", "completion_report"))

	if db == nil || reportID == uuid.Nil {
		return errors.New("completion saga resume: database and report id are required")
	}
	if attemptTimeout <= 0 {
		attemptTimeout = defaultAttemptTimeout
	}

	tx, err := db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin completion saga resume: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var status string
	var fileID *uuid.UUID
	var payload json.RawMessage
	if err = lockReport(ctx, tx, reportID); err != nil {
		return fmt.Errorf("lock completion saga %s: %w", reportID, err)
	}
	err = tx.QueryRow(ctx, `
		SELECT completion_status, completion_file_id
		FROM ticket_reports
		WHERE id=$1`, reportID).Scan(&status, &fileID)
	if err != nil {
		return fmt.Errorf("load completion saga %s: %w", reportID, err)
	}
	err = tx.QueryRow(ctx, `
		SELECT payload
		FROM outbox_events
		WHERE aggregate_id=$1
		  AND event_type='ticket.completion_report.requested.v1'
		ORDER BY created_at
		LIMIT 1`, reportID).Scan(&payload)
	if err != nil {
		return fmt.Errorf("load original completion request %s: %w", reportID, err)
	}
	if status != "FAILED" && status != "COMPENSATED" {
		return fmt.Errorf("completion saga %s is %s, expected FAILED or COMPENSATED", reportID, status)
	}

	eventType := "ticket.completion_report.requested.v1"
	eventPayload := payload
	if fileID != nil {
		var request requestPayload
		if err = json.Unmarshal(payload, &request); err != nil {
			return fmt.Errorf("decode original completion request: %w", err)
		}
		eventType = "ticket.completion_report.compensation_requested.v1"
		eventPayload, err = json.Marshal(map[string]any{
			"work_report_id": reportID,
			"file_id":        fileID,
			"requested_by":   request.RequestedBy,
			"actor_roles":    request.ActorRoles,
		})
		if err == nil {
			_, err = tx.Exec(ctx, `
				UPDATE ticket_reports
				SET completion_status='COMPENSATING', completion_compensation_attempts=1,
					completion_error=NULL, completion_updated_at=now(), updated_at=now()
				WHERE id=$1`, reportID)
		}
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_status='PENDING', completion_attempts=1,
				completion_deadline_at=now()+make_interval(secs => $2),
				completion_error=NULL, completion_updated_at=now(), updated_at=now()
			WHERE id=$1`, reportID, attemptTimeout.Seconds())
	}
	if err != nil {
		return fmt.Errorf("prepare completion saga %s resume: %w", reportID, err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload)
		VALUES($1,'ticket_report',$2,$3,$4)`, uuid.New(), reportID, eventType, eventPayload)
	if err != nil {
		return fmt.Errorf("enqueue completion saga %s resume: %w", reportID, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit completion saga %s resume: %w", reportID, err)
	}
	return nil
}

func (w *Worker) processOne(ctx context.Context) (found bool, err error) {
	ctx, span := telemetry.Tracer("ticket/completion-saga").Start(ctx, "CompletionSaga.Advance")
	defer func() { telemetry.End(span, err) }()
	span.SetAttributes(attribute.String("saga.name", "completion_report"))

	tx, err := w.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin completion saga transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var item candidate
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM ticket_reports
		WHERE completion_status = 'PENDING'
		  AND completion_deadline_at <= now()
		ORDER BY completion_deadline_at
		LIMIT 1`,
	).Scan(&item.id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find expired completion saga: %w", err)
	}
	span.SetAttributes(attribute.String("saga.state", "expired"))
	if err = lockReport(ctx, tx, item.id); err != nil {
		return false, fmt.Errorf("lock expired completion saga %s: %w", item.id, err)
	}
	err = tx.QueryRow(ctx, `
		SELECT completion_attempts
		FROM ticket_reports
		WHERE id=$1
		  AND completion_status='PENDING'
		  AND completion_deadline_at <= now()`, item.id).Scan(&item.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reload expired completion saga %s: %w", item.id, err)
	}
	if item.attempts < w.cfg.MaxAttempts {
		err = tx.QueryRow(ctx, `
			SELECT payload
			FROM outbox_events
			WHERE aggregate_id=$1
			  AND event_type='ticket.completion_report.requested.v1'
			ORDER BY created_at
			LIMIT 1`, item.id).Scan(&item.payload)
		if err != nil {
			return false, fmt.Errorf("load completion request %s: %w", item.id, err)
		}
	}

	if item.attempts >= w.cfg.MaxAttempts {
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_status='FAILED', completion_error='completion report timed out',
				completion_deadline_at=NULL, completion_updated_at=now(), updated_at=now()
			WHERE id=$1`, item.id)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE ticket_reports
			SET completion_attempts=completion_attempts+1,
				completion_deadline_at=now()+make_interval(secs => $2),
				completion_error=NULL, completion_updated_at=now(), updated_at=now()
			WHERE id=$1`, item.id, w.cfg.AttemptTimeout.Seconds())
		if err == nil {
			_, err = tx.Exec(ctx, `
				INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload)
				VALUES($1,'ticket_report',$2,'ticket.completion_report.requested.v1',$3)`,
				uuid.New(), item.id, item.payload)
		}
	}
	if err != nil {
		return false, fmt.Errorf("advance completion saga %s: %w", item.id, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit completion saga %s: %w", item.id, err)
	}
	return true, nil
}

func lockReport(ctx context.Context, tx pgx.Tx, reportID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, $2))`, reportID, completionLockNamespace)
	return err
}
