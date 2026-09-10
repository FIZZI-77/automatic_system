-- +goose Up
-- +goose StatementBegin

CREATE INDEX geo_zones_department_id_idx ON geo_zones(department_id);
CREATE INDEX geo_zones_active_idx ON geo_zones(active);
CREATE UNIQUE INDEX geo_zones_department_name_active_uidx
    ON geo_zones(department_id, lower(name))
    WHERE active = true;
CREATE INDEX geo_zones_zone_gix ON geo_zones USING GIST(zone);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS geo_zones_zone_gix;
DROP INDEX IF EXISTS geo_zones_department_name_active_uidx;
DROP INDEX IF EXISTS geo_zones_active_idx;
DROP INDEX IF EXISTS geo_zones_department_id_idx;

-- +goose StatementEnd
