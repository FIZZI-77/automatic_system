-- +goose Up
-- +goose StatementBegin

CREATE TABLE sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        client_id VARCHAR(100) NOT NULL,
        ip INET,
        user_agent TEXT,
        is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
        revoked_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE sessions CASCADE;

-- +goose StatementEnd