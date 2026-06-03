-- +goose Up
-- +goose StatementBegin

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type VARCHAR(100) NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    request_id VARCHAR(128) NULL,
    trace_id VARCHAR(128) NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    sent_at TIMESTAMP NULL,
    CONSTRAINT outbox_events_status_check CHECK (
        status IN ('PENDING', 'PROCESSING', 'SENT', 'FAILED')
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE outbox_events CASCADE;

-- +goose StatementEnd
