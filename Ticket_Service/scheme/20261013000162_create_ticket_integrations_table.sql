-- +goose Up
-- +goose StatementBegin
CREATE TABLE ticket_integrations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    secret_hash VARCHAR(128) NOT NULL,
    secret_prefix VARCHAR(16) NOT NULL,
    allowed_department_id UUID NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_ticket_integrations_client_id
        CHECK (client_id ~ '^[a-z0-9][a-z0-9_-]{2,99}$')
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE ticket_integrations CASCADE;
-- +goose StatementEnd
