-- +goose Up
ALTER TABLE dispatch_operations
    ADD COLUMN category_id UUID,
    ADD COLUMN priority VARCHAR(32);

-- +goose Down
ALTER TABLE dispatch_operations
    DROP COLUMN IF EXISTS priority,
    DROP COLUMN IF EXISTS category_id;
