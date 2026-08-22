-- +goose Up
CREATE INDEX outbox_events_pending_idx
 ON outbox_events(next_attempt_at, created_at)
 WHERE status IN ('PENDING', 'FAILED');

CREATE INDEX outbox_events_processing_idx
 ON outbox_events(locked_at)
 WHERE status = 'PROCESSING';

-- +goose Down
DROP INDEX IF EXISTS outbox_events_processing_idx;
DROP INDEX IF EXISTS outbox_events_pending_idx;
