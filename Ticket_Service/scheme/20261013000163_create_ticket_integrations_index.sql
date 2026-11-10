-- +goose Up
-- +goose StatementBegin
CREATE INDEX idx_ticket_integrations_active
    ON ticket_integrations(client_id)
    WHERE is_active = true;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_ticket_integrations_active;
-- +goose StatementEnd
