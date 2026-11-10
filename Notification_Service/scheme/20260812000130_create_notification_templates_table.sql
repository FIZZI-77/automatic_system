-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS notification_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('IN_APP', 'PUSH', 'EMAIL', 'SMS')),
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_type, channel)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS notification_templates CASCADE;
-- +goose StatementEnd
