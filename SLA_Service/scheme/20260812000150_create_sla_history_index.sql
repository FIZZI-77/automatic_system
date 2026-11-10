-- +goose Up
-- +goose StatementBegin
CREATE INDEX sla_history_ticket_idx
    ON sla_history(ticket_id, occurred_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX sla_history_ticket_idx;
-- +goose StatementEnd
