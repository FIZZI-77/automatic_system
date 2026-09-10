-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE brigade_zones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brigade_id UUID NOT NULL REFERENCES brigades(id) ON DELETE CASCADE,
    department_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    zone GEOGRAPHY(GEOMETRY, 4326) NOT NULL,
    priority INT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT brigade_zones_geometry_type_check CHECK (
        GeometryType(zone::geometry) IN ('POLYGON', 'MULTIPOLYGON')
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE brigade_zones CASCADE;

-- +goose StatementEnd
