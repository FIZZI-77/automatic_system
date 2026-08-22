-- +goose Up
CREATE TABLE routing_inbox_events (
    event_id UUID PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    partition_id INT NOT NULL,
    message_offset BIGINT NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE brigade_route_projection (
    brigade_id UUID PRIMARY KEY REFERENCES brigades(id) ON DELETE CASCADE,
    route_id UUID NOT NULL,
    ticket_id UUID NOT NULL,
    route_status VARCHAR(32) NOT NULL,
    revision INT NOT NULL,
    source_updated_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT brigade_route_projection_status_check CHECK (
        route_status IN ('PLANNED', 'ACTIVE', 'COMPLETED', 'CANCELLED')
    )
);

CREATE UNIQUE INDEX brigade_route_projection_route_id_idx
    ON brigade_route_projection(route_id);

-- +goose Down
DROP TABLE IF EXISTS brigade_route_projection;
DROP TABLE IF EXISTS routing_inbox_events;
