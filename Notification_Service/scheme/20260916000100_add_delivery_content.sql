-- +goose Up
ALTER TABLE deliveries ADD COLUMN title text NOT NULL DEFAULT '';
ALTER TABLE deliveries ADD COLUMN body text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE deliveries DROP COLUMN body;
ALTER TABLE deliveries DROP COLUMN title;
