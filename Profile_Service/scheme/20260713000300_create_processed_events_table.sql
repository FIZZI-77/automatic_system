-- +goose Up
-- +goose StatementBegin

CREATE TABLE processed_events (
    event_id UUID PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    source_service VARCHAR(128) NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE processed_events CASCADE;

-- +goose StatementEnd
