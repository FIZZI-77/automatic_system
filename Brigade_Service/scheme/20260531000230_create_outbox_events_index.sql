-- +goose Up
-- +goose StatementBegin

CREATE INDEX outbox_events_status_created_at_idx ON outbox_events(status, created_at);
CREATE INDEX outbox_events_aggregate_id_idx ON outbox_events(aggregate_id);
CREATE INDEX outbox_events_event_type_idx ON outbox_events(event_type);
CREATE INDEX outbox_events_request_id_idx ON outbox_events(request_id);
CREATE INDEX outbox_events_trace_id_idx ON outbox_events(trace_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS outbox_events_trace_id_idx;
DROP INDEX IF EXISTS outbox_events_request_id_idx;
DROP INDEX IF EXISTS outbox_events_event_type_idx;
DROP INDEX IF EXISTS outbox_events_aggregate_id_idx;
DROP INDEX IF EXISTS outbox_events_status_created_at_idx;

-- +goose StatementEnd
