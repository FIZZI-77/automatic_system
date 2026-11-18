-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ticket_slas (
    id UUID PRIMARY KEY,
    ticket_id UUID NOT NULL UNIQUE,
    rule_id UUID NOT NULL REFERENCES sla_rules(id),
    department_id UUID NOT NULL,
    category_id UUID NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'COMPLETED', 'CANCELLED')),
    response_deadline TIMESTAMPTZ NOT NULL,
    resolution_deadline TIMESTAMPTZ NOT NULL,
    responded_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    response_breached BOOLEAN NOT NULL DEFAULT false,
    resolution_breached BOOLEAN NOT NULL DEFAULT false,
    response_warning_sent BOOLEAN NOT NULL DEFAULT false,
    resolution_warning_sent BOOLEAN NOT NULL DEFAULT false,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ticket_slas CASCADE;
-- +goose StatementEnd
