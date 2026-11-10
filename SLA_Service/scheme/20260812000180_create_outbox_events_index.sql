-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS sla_outbox_pending_idx
    ON outbox_events(status, next_attempt_at, created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS sla_outbox_pending_idx;
-- +goose StatementEnd
