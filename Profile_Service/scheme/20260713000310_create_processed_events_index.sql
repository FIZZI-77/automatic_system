-- +goose Up
-- +goose StatementBegin

CREATE INDEX processed_events_source_service_idx ON processed_events(source_service);
CREATE INDEX processed_events_processed_at_idx ON processed_events(processed_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS processed_events_processed_at_idx;
DROP INDEX IF EXISTS processed_events_source_service_idx;

-- +goose StatementEnd
