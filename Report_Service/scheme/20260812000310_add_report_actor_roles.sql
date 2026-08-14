-- +goose Up
ALTER TABLE reports ADD COLUMN actor_roles text[] NOT NULL DEFAULT '{}';
-- +goose Down
ALTER TABLE reports DROP COLUMN actor_roles;
