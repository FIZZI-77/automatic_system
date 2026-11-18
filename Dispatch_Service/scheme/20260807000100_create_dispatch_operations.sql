-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE dispatch_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id UUID NOT NULL,
    brigade_id UUID,
    route_id UUID,
    mode VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL,
    version INT NOT NULL DEFAULT 1 CHECK (version > 0),
    requested_by UUID NOT NULL,
    failure_reason TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dispatch_operations_status_check CHECK (
        status IN ('PENDING','RESERVED','CONFIRMING','ASSIGNED','FAILED','CANCELLED','EXPIRED')
    )
);

-- +goose Down
DROP TABLE IF EXISTS dispatch_operations;
