-- +goose Up
ALTER TABLE dispatch_operations
    ADD COLUMN department_id UUID,
    ADD COLUMN failure_code VARCHAR(64);

CREATE TABLE dispatch_outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(96) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dispatch_outbox_status_check CHECK (
        status IN ('PENDING', 'PROCESSING', 'SENT', 'FAILED')
    )
);

CREATE INDEX dispatch_outbox_pending_idx
    ON dispatch_outbox_events(next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'FAILED');

CREATE INDEX dispatch_outbox_processing_idx
    ON dispatch_outbox_events(locked_at)
    WHERE status = 'PROCESSING';

-- +goose Down
DROP TABLE IF EXISTS dispatch_outbox_events;
ALTER TABLE dispatch_operations
    DROP COLUMN IF EXISTS failure_code,
    DROP COLUMN IF EXISTS department_id;
