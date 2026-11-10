-- +goose Up
-- +goose StatementBegin
CREATE TABLE event_inbox (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    topic TEXT NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE event_inbox CASCADE;
-- +goose StatementEnd
