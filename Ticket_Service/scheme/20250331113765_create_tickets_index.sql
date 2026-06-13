-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_tickets_department_created_at ON tickets(department_id, created_at DESC);
CREATE INDEX idx_tickets_department_status_created_at ON tickets(department_id, status, created_at DESC);
CREATE INDEX idx_tickets_user_created_at ON tickets(user_id, created_at DESC);
CREATE INDEX idx_tickets_brigade_created_at ON tickets(brigade_id, created_at DESC) WHERE brigade_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_tickets_department_created_at;
DROP INDEX idx_tickets_department_status_created_at;
DROP INDEX idx_tickets_user_created_at;
DROP INDEX idx_tickets_brigade_created_at;

-- +goose StatementEnd
