-- +goose Up
-- +goose StatementBegin
CREATE INDEX audit_entries_recorded_idx
    ON audit_entries(recorded_at DESC);
CREATE INDEX audit_entries_actor_idx
    ON audit_entries(actor_id, recorded_at DESC)
    WHERE actor_id IS NOT NULL;
CREATE INDEX audit_entries_entity_idx
    ON audit_entries(entity_type, entity_id, recorded_at DESC)
    WHERE entity_id IS NOT NULL;
CREATE INDEX audit_entries_action_idx
    ON audit_entries(action, recorded_at DESC);
CREATE INDEX audit_entries_request_idx
    ON audit_entries(request_id)
    WHERE request_id IS NOT NULL;
CREATE INDEX audit_entries_trace_idx
    ON audit_entries(trace_id)
    WHERE trace_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX audit_entries_trace_idx;
DROP INDEX audit_entries_request_idx;
DROP INDEX audit_entries_action_idx;
DROP INDEX audit_entries_entity_idx;
DROP INDEX audit_entries_actor_idx;
DROP INDEX audit_entries_recorded_idx;
-- +goose StatementEnd
