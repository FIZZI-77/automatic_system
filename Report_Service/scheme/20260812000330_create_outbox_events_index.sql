-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS report_outbox_pending_idx
    ON outbox_events(next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'FAILED');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS report_outbox_pending_idx;
-- +goose StatementEnd
