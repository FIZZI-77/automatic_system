CREATE DATABASE IF NOT EXISTS analytics;
CREATE TABLE IF NOT EXISTS analytics.domain_events (
    topic LowCardinality(String),
    event_id String,
    event_type LowCardinality(String),
    entity_id String,
    ticket_id String,
    department_id String,
    category_id String,
    brigade_id String,
    user_id String,
    priority LowCardinality(String),
    status LowCardinality(String),
    latitude Nullable(Float64),
    longitude Nullable(Float64),
    payload String,
    occurred_at DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (topic, event_id)
TTL occurred_at + INTERVAL 5 YEAR DELETE;
