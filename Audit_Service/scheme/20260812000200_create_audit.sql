-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE audit_entries(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id text NOT NULL,
    topic text NOT NULL,
    action text NOT NULL,
    actor_id uuid,
    entity_type text,
    entity_id text,
    request_id text,
    trace_id text,
    data jsonb NOT NULL,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(topic,event_id)
);
CREATE INDEX audit_entries_recorded_idx ON audit_entries(recorded_at DESC);
CREATE INDEX audit_entries_actor_idx ON audit_entries(actor_id,recorded_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_entries_entity_idx ON audit_entries(entity_type,entity_id,recorded_at DESC) WHERE entity_id IS NOT NULL;
CREATE INDEX audit_entries_action_idx ON audit_entries(action,recorded_at DESC);
CREATE INDEX audit_entries_request_idx ON audit_entries(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX audit_entries_trace_idx ON audit_entries(trace_id) WHERE trace_id IS NOT NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_entries_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit entries are immutable';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER audit_entries_no_update BEFORE UPDATE OR DELETE ON audit_entries
FOR EACH ROW EXECUTE FUNCTION audit_entries_immutable();

-- +goose Down
DROP TABLE audit_entries;
DROP FUNCTION audit_entries_immutable();
