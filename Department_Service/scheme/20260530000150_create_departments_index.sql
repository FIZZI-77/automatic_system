-- +goose Up
-- +goose StatementBegin

CREATE INDEX departments_status_idx ON departments(status);
CREATE INDEX departments_created_at_idx ON departments(created_at);
CREATE INDEX departments_updated_at_idx ON departments(updated_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS departments_updated_at_idx;
DROP INDEX IF EXISTS departments_created_at_idx;
DROP INDEX IF EXISTS departments_status_idx;

-- +goose StatementEnd

