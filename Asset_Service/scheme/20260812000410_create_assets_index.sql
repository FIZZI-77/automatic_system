-- +goose Up
CREATE INDEX IF NOT EXISTS assets_geometry_idx ON assets USING gist (geometry);
CREATE INDEX IF NOT EXISTS assets_filter_idx ON assets (department_id, type, status, risk_level);

-- +goose Down
DROP INDEX IF EXISTS assets_filter_idx;
DROP INDEX IF EXISTS assets_geometry_idx;
