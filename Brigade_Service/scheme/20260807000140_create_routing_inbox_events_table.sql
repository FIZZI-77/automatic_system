-- +goose Up
-- +goose StatementBegin
CREATE TABLE routing_inbox_events (
    event_id UUID PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    partition_id INT NOT NULL,
    message_offset BIGINT NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMP NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE routing_inbox_events CASCADE;
-- +goose StatementEnd
