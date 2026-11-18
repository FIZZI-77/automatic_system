-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE sla_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    department_id UUID,
    category_id UUID,
    priority TEXT CHECK (priority IS NULL OR priority IN ('LOW', 'MEDIUM', 'HIGH', 'EMERGENCY')),
    response_seconds BIGINT NOT NULL CHECK (response_seconds > 0),
    resolution_seconds BIGINT NOT NULL CHECK (resolution_seconds >= response_seconds),
    warning_percent INTEGER NOT NULL DEFAULT 80 CHECK (warning_percent BETWEEN 1 AND 99),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE sla_rules CASCADE;
-- +goose StatementEnd
