-- +goose Up
ALTER TABLE dispatch_operations
    ADD COLUMN failure_stage VARCHAR(64);

-- +goose Down
ALTER TABLE dispatch_operations
    DROP COLUMN IF EXISTS failure_stage;
