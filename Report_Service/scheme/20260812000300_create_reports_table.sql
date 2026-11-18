-- +goose Up
-- +goose StatementBegin
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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE reports CASCADE;
-- +goose StatementEnd
