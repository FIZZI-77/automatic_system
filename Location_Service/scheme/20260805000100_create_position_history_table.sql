-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE position_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    vehicle_id UUID NOT NULL,
    brigade_id UUID NOT NULL,
    sequence BIGINT NOT NULL,
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    position GEOGRAPHY(POINT, 4326) GENERATED ALWAYS AS (
        ST_SetSRID(ST_MakePoint(longitude, latitude), 4326)::geography
    ) STORED,
    speed_kmh DOUBLE PRECISION NOT NULL DEFAULT 0,
    heading DOUBLE PRECISION NOT NULL DEFAULT 0,
    accuracy_meters DOUBLE PRECISION NOT NULL DEFAULT 0,
    altitude_meters DOUBLE PRECISION NULL,
    simulated BOOLEAN NOT NULL DEFAULT false,
    recorded_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT position_history_device_id_not_blank_check CHECK (length(btrim(device_id)) BETWEEN 1 AND 128),
    CONSTRAINT position_history_sequence_check CHECK (sequence > 0),
    CONSTRAINT position_history_latitude_check CHECK (latitude BETWEEN -90 AND 90),
    CONSTRAINT position_history_longitude_check CHECK (longitude BETWEEN -180 AND 180),
    CONSTRAINT position_history_speed_check CHECK (speed_kmh >= 0),
    CONSTRAINT position_history_heading_check CHECK (heading >= 0 AND heading < 360),
    CONSTRAINT position_history_accuracy_check CHECK (accuracy_meters >= 0),
    CONSTRAINT position_history_geometry_type_check CHECK (GeometryType(position::geometry) = 'POINT')
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE position_history CASCADE;

-- +goose StatementEnd
