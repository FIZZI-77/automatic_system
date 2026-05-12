-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_outbox_events_status_created_at ON outbox_events(status, created_at);
CREATE INDEX idx_outbox_events_aggregate_id ON outbox_events(aggregate_id);
CREATE INDEX idx_outbox_events_event_type ON outbox_events(event_type);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_outbox_events_status_created_at;
DROP INDEX idx_outbox_events_aggregate_id;
DROP INDEX idx_outbox_events_event_type;

-- +goose StatementEnd