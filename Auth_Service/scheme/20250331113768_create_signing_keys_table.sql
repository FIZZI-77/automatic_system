-- +goose Up
-- +goose StatementBegin



CREATE TABLE signing_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        kid VARCHAR(100) NOT NULL UNIQUE,
        algorithm VARCHAR(20) NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ
);


-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE signing_keys CASCADE;

-- +goose StatementEnd