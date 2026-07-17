-- +goose Up
-- +goose StatementBegin

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type VARCHAR(100) NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ NULL,
    CONSTRAINT outbox_events_status_check CHECK (
        status IN ('PENDING', 'PROCESSING', 'SENT', 'FAILED')
    ),
    CONSTRAINT outbox_events_attempts_check CHECK (attempts >= 0),
    CONSTRAINT outbox_events_sent_at_check CHECK (
        status <> 'SENT' OR sent_at IS NOT NULL
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE outbox_events CASCADE;

-- +goose StatementEnd
