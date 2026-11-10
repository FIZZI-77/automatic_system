-- +goose Up
-- +goose StatementBegin
CREATE INDEX inbox_events_processed_at_idx ON inbox_events(processed_at);
CREATE INDEX inbox_events_type_idx ON inbox_events(event_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS inbox_events_type_idx;
DROP INDEX IF EXISTS inbox_events_processed_at_idx;
-- +goose StatementEnd
