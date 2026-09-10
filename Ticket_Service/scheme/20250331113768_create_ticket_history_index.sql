-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_ticket_status_history_ticket_created_at ON ticket_status_history(ticket_id, created_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_ticket_status_history_ticket_created_at;

-- +goose StatementEnd
