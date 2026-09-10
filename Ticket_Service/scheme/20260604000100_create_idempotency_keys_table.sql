-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_key VARCHAR(128) NOT NULL DEFAULT '',
    operation VARCHAR(100) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_hash VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PROCESSING',
    response JSONB NULL,
    error TEXT NULL,
    resource_type VARCHAR(100) NULL,
    resource_id UUID NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    expires_at TIMESTAMP NOT NULL DEFAULT now() + INTERVAL '24 hours',
    CONSTRAINT idempotency_keys_status_check CHECK (
        status IN ('PROCESSING', 'COMPLETED', 'FAILED')
    ),
    CONSTRAINT idempotency_keys_unique_key UNIQUE (
        actor_key,
        operation,
        idempotency_key
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE idempotency_keys CASCADE;

-- +goose StatementEnd
