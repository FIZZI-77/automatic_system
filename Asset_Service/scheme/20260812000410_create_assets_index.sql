-- +goose Up
CREATE INDEX assets_geometry_idx ON assets USING gist (geometry);
CREATE INDEX assets_filter_idx ON assets (department_id, type, status, risk_level);

-- +goose Down
DROP INDEX assets_filter_idx;
DROP INDEX assets_geometry_idx;
