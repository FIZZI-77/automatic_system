-- +goose Up
-- +goose StatementBegin

CREATE TABLE departments (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT departments_status_check CHECK (status IN ('ACTIVE', 'INACTIVE', 'ARCHIVED'))
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE departments CASCADE;

-- +goose StatementEnd

