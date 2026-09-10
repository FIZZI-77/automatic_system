-- +goose Up
-- +goose StatementBegin

CREATE TABLE geo_zones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    department_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    zone GEOGRAPHY(GEOMETRY, 4326) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT geo_zones_name_not_blank_check CHECK (length(btrim(name)) BETWEEN 1 AND 255),
    CONSTRAINT geo_zones_geometry_type_check CHECK (
        GeometryType(zone::geometry) IN ('POLYGON', 'MULTIPOLYGON')
    ),
    CONSTRAINT geo_zones_geometry_valid_check CHECK (ST_IsValid(zone::geometry))
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE geo_zones CASCADE;

-- +goose StatementEnd
