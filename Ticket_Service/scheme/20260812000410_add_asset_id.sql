-- +goose Up
ALTER TABLE tickets ADD COLUMN asset_id uuid;
CREATE INDEX tickets_asset_id_idx ON tickets(asset_id) WHERE asset_id IS NOT NULL;
-- +goose Down
DROP INDEX tickets_asset_id_idx;
ALTER TABLE tickets DROP COLUMN asset_id;
