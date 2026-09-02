CREATE DATABASE IF NOT EXISTS analytics;
CREATE TABLE IF NOT EXISTS analytics.domain_events (
    topic LowCardinality(String),
    event_id String,
    event_type LowCardinality(String),
    entity_id String,
    ticket_id String,
    department_id String,
    category_id String,
    asset_id String,
    brigade_id String,
    shift_id String,
    user_id String,
    member_id String,
    member_status LowCardinality(String),
    availability_status LowCardinality(String),
    member_role LowCardinality(String),
    member_active Nullable(Bool),
    route_id String,
    trace_id String,
    priority LowCardinality(String),
    status LowCardinality(String),
    assignment_mode LowCardinality(String),
    failure_code LowCardinality(String),
    failure_stage LowCardinality(String),
    success Nullable(Bool),
    calculation_duration_ms Nullable(Float64),
    candidate_count Nullable(UInt64),
    reachable_candidate_count Nullable(UInt64),
    engine LowCardinality(String),
    travel_mode LowCardinality(String),
    latitude Nullable(Float64),
    longitude Nullable(Float64),
    route_revision Nullable(UInt32),
    distance_meters Nullable(Float64),
    duration_seconds Nullable(Float64),
    speed_kmh Nullable(Float64),
    accuracy_meters Nullable(Float64),
    destination_latitude Nullable(Float64),
    destination_longitude Nullable(Float64),
    payload String,
    occurred_at DateTime64(3, 'UTC'),
    event_version UInt32 DEFAULT 1,
    projection_eligible Bool DEFAULT true,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (topic, event_id)
TTL occurred_at + INTERVAL 5 YEAR DELETE;

ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS route_id String AFTER user_id;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS trace_id String AFTER route_id;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS assignment_mode LowCardinality(String) AFTER status;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS failure_code LowCardinality(String) AFTER assignment_mode;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS failure_stage LowCardinality(String) AFTER failure_code;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS success Nullable(Bool) AFTER failure_code;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS calculation_duration_ms Nullable(Float64) AFTER success;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS engine LowCardinality(String) AFTER calculation_duration_ms;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS travel_mode LowCardinality(String) AFTER engine;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS event_version UInt32 DEFAULT 1 AFTER occurred_at;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS projection_eligible Bool DEFAULT true AFTER event_version;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS member_id String AFTER user_id;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS member_status LowCardinality(String) AFTER member_id;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS availability_status LowCardinality(String) AFTER member_status;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS member_role LowCardinality(String) AFTER availability_status;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS member_active Nullable(Bool) AFTER member_role;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS candidate_count Nullable(UInt64) AFTER calculation_duration_ms;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS reachable_candidate_count Nullable(UInt64) AFTER candidate_count;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS route_revision Nullable(UInt32) AFTER longitude;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS distance_meters Nullable(Float64) AFTER route_revision;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS duration_seconds Nullable(Float64) AFTER distance_meters;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS speed_kmh Nullable(Float64) AFTER duration_seconds;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS accuracy_meters Nullable(Float64) AFTER speed_kmh;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS destination_latitude Nullable(Float64) AFTER accuracy_meters;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS destination_longitude Nullable(Float64) AFTER destination_latitude;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS asset_id String AFTER category_id;
ALTER TABLE analytics.domain_events ADD COLUMN IF NOT EXISTS shift_id String AFTER brigade_id;

CREATE TABLE IF NOT EXISTS analytics.domain_events_projection_v1 AS analytics.domain_events;
ALTER TABLE analytics.domain_events_projection_v1 ADD COLUMN IF NOT EXISTS asset_id String AFTER category_id;
ALTER TABLE analytics.domain_events_projection_v1 ADD COLUMN IF NOT EXISTS shift_id String AFTER brigade_id;
ALTER TABLE analytics.domain_events_projection_v1 ADD COLUMN IF NOT EXISTS speed_kmh Nullable(Float64) AFTER duration_seconds;
ALTER TABLE analytics.domain_events_projection_v1 ADD COLUMN IF NOT EXISTS accuracy_meters Nullable(Float64) AFTER speed_kmh;
ALTER TABLE analytics.domain_events_projection_v1 ADD COLUMN IF NOT EXISTS destination_latitude Nullable(Float64) AFTER accuracy_meters;
ALTER TABLE analytics.domain_events_projection_v1 ADD COLUMN IF NOT EXISTS destination_longitude Nullable(Float64) AFTER destination_latitude;

CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.domain_events_projection_v1_mv
TO analytics.domain_events_projection_v1
AS SELECT * FROM analytics.domain_events;

-- ReplacingMergeTree makes this backfill idempotent by (topic,event_id,version).
-- FINAL readers see one row even when the bootstrap job is re-run.
INSERT INTO analytics.domain_events_projection_v1
SELECT * FROM analytics.domain_events;
