-- +goose Up
-- +goose StatementBegin
CREATE INDEX sla_outbox_pending_idx
    ON outbox_events(status, next_attempt_at, created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX sla_outbox_pending_idx;
-- +goose StatementEnd
