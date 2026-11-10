-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ticket_event_inbox (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    ticket_id UUID NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ticket_event_inbox CASCADE;
-- +goose StatementEnd
