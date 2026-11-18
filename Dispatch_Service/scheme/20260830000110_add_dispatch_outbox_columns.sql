-- +goose Up
-- +goose StatementBegin
ALTER TABLE dispatch_operations
    ADD COLUMN department_id UUID,
    ADD COLUMN failure_code VARCHAR(64);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE dispatch_operations
    DROP COLUMN IF EXISTS failure_code,
    DROP COLUMN IF EXISTS department_id;
-- +goose StatementEnd
