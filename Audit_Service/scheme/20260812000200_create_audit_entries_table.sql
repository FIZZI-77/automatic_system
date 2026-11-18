-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE audit_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id TEXT NOT NULL,
    topic TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id UUID,
    entity_type TEXT,
    entity_id TEXT,
    request_id TEXT,
    trace_id TEXT,
    data JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (topic, event_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE audit_entries CASCADE;
-- +goose StatementEnd
