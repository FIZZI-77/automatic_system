-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id text UNIQUE,
    department_id uuid NOT NULL,
    type text NOT NULL,
    name text NOT NULL,
    address text NOT NULL DEFAULT '',
    district text NOT NULL DEFAULT '',
    municipality text NOT NULL DEFAULT '',
    geometry geometry(Geometry, 4326) NOT NULL,
    status text NOT NULL DEFAULT 'ACTIVE',
    model text NOT NULL DEFAULT '',
    serial_number text NOT NULL DEFAULT '',
    installation_year int,
    service_life_years int,
    warranty_until timestamptz,
    owner text NOT NULL DEFAULT '',
    service_organization text NOT NULL DEFAULT '',
    contractor text NOT NULL DEFAULT '',
    inspection_interval_days int NOT NULL DEFAULT 365,
    response_norm_minutes int NOT NULL DEFAULT 60,
    repair_norm_minutes int NOT NULL DEFAULT 1440,
    criticality double precision NOT NULL DEFAULT .5,
    risk_score double precision NOT NULL DEFAULT 0,
    risk_level text NOT NULL DEFAULT 'LOW',
    last_repair_at timestamptz,
    next_inspection_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE assets;
