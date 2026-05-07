-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_tickets_department_id ON tickets(department_id);
CREATE INDEX idx_tickets_category_id ON tickets(category_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_priority ON tickets(priority);
CREATE INDEX idx_tickets_department_status ON tickets(department_id, status);
CREATE INDEX idx_tickets_department_created_at ON tickets(department_id, created_at);
CREATE INDEX idx_tickets_user_id ON tickets(user_id);
CREATE INDEX idx_tickets_brigade_id ON tickets(brigade_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_tickets_department_id;
DROP INDEX idx_tickets_category_id;
DROP INDEX idx_tickets_status;
DROP INDEX idx_tickets_priority;
DROP INDEX idx_tickets_department_status;
DROP INDEX idx_tickets_department_created_at;
DROP INDEX idx_tickets_user_id;
DROP INDEX idx_tickets_brigade_id;

-- +goose StatementEnd