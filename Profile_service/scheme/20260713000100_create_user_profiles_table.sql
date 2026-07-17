-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    phone VARCHAR(32) NULL,
    avatar_file_id UUID NULL,
    preferred_contact_method VARCHAR(16) NOT NULL DEFAULT 'EMAIL',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_profiles_full_name_not_blank_check CHECK (
        length(btrim(full_name)) BETWEEN 2 AND 255
    ),
    CONSTRAINT user_profiles_phone_format_check CHECK (
        phone IS NULL OR phone ~ '^\+[0-9]{8,15}$'
    ),
    CONSTRAINT user_profiles_contact_method_check CHECK (
        preferred_contact_method IN ('EMAIL', 'PHONE', 'PUSH')
    ),
    CONSTRAINT user_profiles_phone_contact_check CHECK (
        preferred_contact_method <> 'PHONE' OR phone IS NOT NULL
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE user_profiles CASCADE;

-- +goose StatementEnd
