-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requested_by UUID NOT NULL,
    actor_roles TEXT[] NOT NULL DEFAULT '{}',
    name VARCHAR(160) NOT NULL,
    type VARCHAR(32) NOT NULL CHECK (
        type IN ('TICKET_OVERVIEW', 'SLA_SUMMARY', 'TICKET_BREAKDOWN', 'DAILY_TICKETS')
    ),
    format VARCHAR(8) NOT NULL CHECK (format IN ('PDF', 'XLSX', 'CSV')),
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING' CHECK (
        status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELED')
    ),
    filter JSONB NOT NULL DEFAULT '{}',
    file_id UUID,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX reports_requested_created_idx ON reports(requested_by, created_at DESC);
CREATE INDEX reports_pending_idx ON reports(created_at) WHERE status = 'PENDING';

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX report_outbox_pending_idx
    ON outbox_events(next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'FAILED');

-- +goose Down
DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS reports;
