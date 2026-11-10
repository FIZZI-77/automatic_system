-- +goose Up
-- +goose StatementBegin
CREATE TABLE completion_report_inbox (
    event_id UUID PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE completion_report_inbox CASCADE;
-- +goose StatementEnd
