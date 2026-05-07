-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_ticket_status_history_ticket_id ON ticket_status_history(ticket_id);
CREATE INDEX idx_ticket_status_history_created_at ON ticket_status_history(created_at);
CREATE INDEX idx_ticket_status_history_ticket_created_at ON ticket_status_history(ticket_id, created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_ticket_status_history_ticket_id;
DROP INDEX idx_ticket_status_history_created_at;
DROP INDEX idx_ticket_status_history_ticket_created_at;

-- +goose StatementEnd