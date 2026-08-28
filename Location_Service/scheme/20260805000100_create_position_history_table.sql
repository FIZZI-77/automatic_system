-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE position_history (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
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
    CONSTRAINT position_history_pkey PRIMARY KEY (recorded_at, id),
    CONSTRAINT position_history_device_id_not_blank_check CHECK (length(btrim(device_id)) BETWEEN 1 AND 128),
    CONSTRAINT position_history_sequence_check CHECK (sequence > 0),
    CONSTRAINT position_history_latitude_check CHECK (latitude BETWEEN -90 AND 90),
    CONSTRAINT position_history_longitude_check CHECK (longitude BETWEEN -180 AND 180),
    CONSTRAINT position_history_speed_check CHECK (speed_kmh >= 0),
    CONSTRAINT position_history_heading_check CHECK (heading >= 0 AND heading < 360),
    CONSTRAINT position_history_accuracy_check CHECK (accuracy_meters >= 0),
    CONSTRAINT position_history_geometry_type_check CHECK (GeometryType(position::geometry) = 'POINT')
) PARTITION BY RANGE(recorded_at);

CREATE TABLE position_history_default
    PARTITION OF position_history DEFAULT;

CREATE OR REPLACE FUNCTION ensure_position_history_partitions(months_ahead INTEGER DEFAULT 3)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    month_start TIMESTAMPTZ := date_trunc('month', now());
    upper_bound TIMESTAMPTZ := date_trunc('month', now()) + make_interval(months => months_ahead + 1);
    partition_name TEXT;
    created_count INTEGER := 0;
BEGIN
    WHILE month_start < upper_bound LOOP
        partition_name := 'position_history_' || to_char(month_start, 'YYYY_MM');
        IF to_regclass(partition_name) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF position_history FOR VALUES FROM (%L) TO (%L)',
                partition_name,
                month_start,
                month_start + interval '1 month'
            );
            created_count := created_count + 1;
        END IF;
        month_start := month_start + interval '1 month';
    END LOOP;
    RETURN created_count;
END;
$$;

SELECT ensure_position_history_partitions();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP FUNCTION IF EXISTS ensure_position_history_partitions(INTEGER);
DROP TABLE position_history CASCADE;

-- +goose StatementEnd
