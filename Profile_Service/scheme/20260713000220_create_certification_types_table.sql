-- +goose Up
-- +goose StatementBegin

CREATE TABLE certification_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NULL,
    default_validity_days INTEGER NULL,
    requires_file BOOLEAN NOT NULL DEFAULT true,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT certification_types_code_not_blank_check CHECK (
        length(btrim(code)) BETWEEN 2 AND 64
    ),
    CONSTRAINT certification_types_name_not_blank_check CHECK (
        length(btrim(name)) BETWEEN 2 AND 255
    ),
    CONSTRAINT certification_types_default_validity_days_check CHECK (
        default_validity_days IS NULL OR default_validity_days > 0
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE certification_types CASCADE;

-- +goose StatementEnd
