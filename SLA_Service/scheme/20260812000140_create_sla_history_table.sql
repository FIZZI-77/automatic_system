-- +goose Up
-- +goose StatementBegin
CREATE TABLE sla_history (
    id UUID PRIMARY KEY,
    ticket_sla_id UUID NOT NULL REFERENCES ticket_slas(id),
    ticket_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE sla_history CASCADE;
-- +goose StatementEnd
