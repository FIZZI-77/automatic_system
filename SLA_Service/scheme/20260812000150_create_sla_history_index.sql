-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS sla_history_ticket_idx
    ON sla_history(ticket_id, occurred_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS sla_history_ticket_idx;
-- +goose StatementEnd
