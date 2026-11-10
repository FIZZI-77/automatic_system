-- +goose Up
-- +goose StatementBegin
CREATE TABLE inbox_events (
    event_id UUID PRIMARY KEY,
    source_service VARCHAR(100) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    partition_id INTEGER NOT NULL,
    message_offset BIGINT NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    event_version INTEGER NOT NULL DEFAULT 1,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (topic, partition_id, message_offset)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE inbox_events CASCADE;
-- +goose StatementEnd
