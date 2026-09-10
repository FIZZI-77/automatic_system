-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE brigades (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    department_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'INACTIVE',
    specialization VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    deactivated_at TIMESTAMP NULL,
    archived_at TIMESTAMP NULL,
    CONSTRAINT brigades_status_check CHECK (
        status IN (
            'ACTIVE',
            'INACTIVE',
            'AVAILABLE',
            'BUSY',
            'ON_ROUTE',
            'ON_SITE',
            'OFFLINE',
            'ARCHIVED'
        )
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE brigades CASCADE;

-- +goose StatementEnd
