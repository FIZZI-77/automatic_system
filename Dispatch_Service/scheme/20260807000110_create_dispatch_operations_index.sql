-- +goose Up
-- +goose StatementBegin
CREATE UNIQUE INDEX dispatch_one_open_ticket_idx
    ON dispatch_operations(ticket_id)
    WHERE status IN ('PENDING', 'RESERVED', 'CONFIRMING');
CREATE UNIQUE INDEX dispatch_one_reserved_brigade_idx
    ON dispatch_operations(brigade_id)
    WHERE status IN ('RESERVED', 'CONFIRMING');
CREATE INDEX dispatch_expiry_idx
    ON dispatch_operations(status, expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS dispatch_expiry_idx;
DROP INDEX IF EXISTS dispatch_one_reserved_brigade_idx;
DROP INDEX IF EXISTS dispatch_one_open_ticket_idx;
-- +goose StatementEnd
