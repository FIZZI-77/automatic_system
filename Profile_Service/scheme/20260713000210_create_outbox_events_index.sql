-- +goose Up
-- +goose StatementBegin

CREATE INDEX outbox_events_status_created_at_idx
    ON outbox_events(status, created_at);
CREATE INDEX outbox_events_retry_idx
    ON outbox_events(status, next_attempt_at, created_at);
CREATE INDEX outbox_events_aggregate_idx
    ON outbox_events(aggregate_type, aggregate_id);
CREATE INDEX outbox_events_event_type_idx ON outbox_events(event_type);
CREATE INDEX outbox_events_locked_at_idx
    ON outbox_events(locked_at)
    WHERE locked_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS outbox_events_locked_at_idx;
DROP INDEX IF EXISTS outbox_events_event_type_idx;
DROP INDEX IF EXISTS outbox_events_aggregate_idx;
DROP INDEX IF EXISTS outbox_events_retry_idx;
DROP INDEX IF EXISTS outbox_events_status_created_at_idx;

-- +goose StatementEnd
