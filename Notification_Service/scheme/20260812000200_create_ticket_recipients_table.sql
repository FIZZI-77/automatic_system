-- +goose Up
-- +goose StatementBegin
CREATE TABLE ticket_recipients (
    ticket_id UUID PRIMARY KEY,
    user_id UUID,
    department_id UUID,
    brigade_id UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE ticket_recipients CASCADE;
-- +goose StatementEnd
