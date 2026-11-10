-- +goose Up
-- +goose StatementBegin
CREATE INDEX dispatch_outbox_pending_idx
    ON dispatch_outbox_events(next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'FAILED');
CREATE INDEX dispatch_outbox_processing_idx
    ON dispatch_outbox_events(locked_at)
    WHERE status = 'PROCESSING';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS dispatch_outbox_processing_idx;
DROP INDEX IF EXISTS dispatch_outbox_pending_idx;
-- +goose StatementEnd
