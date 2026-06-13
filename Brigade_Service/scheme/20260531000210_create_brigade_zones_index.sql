-- +goose Up
-- +goose StatementBegin

CREATE INDEX brigade_zones_brigade_id_idx ON brigade_zones(brigade_id);
CREATE INDEX brigade_zones_department_id_idx ON brigade_zones(department_id);
CREATE INDEX brigade_zones_active_idx ON brigade_zones(active);
CREATE INDEX brigade_zones_priority_idx ON brigade_zones(priority);
CREATE INDEX brigade_zones_zone_gix ON brigade_zones USING GIST(zone);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS brigade_zones_zone_gix;
DROP INDEX IF EXISTS brigade_zones_priority_idx;
DROP INDEX IF EXISTS brigade_zones_active_idx;
DROP INDEX IF EXISTS brigade_zones_department_id_idx;
DROP INDEX IF EXISTS brigade_zones_brigade_id_idx;

-- +goose StatementEnd
