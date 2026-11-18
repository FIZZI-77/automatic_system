-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS brigade_route_projection (
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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS brigade_route_projection CASCADE;
-- +goose StatementEnd
