-- +goose Up
-- +goose StatementBegin

CREATE TABLE refresh_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
        revoked_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        replaced_by_token_id UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE refresh_tokens CASCADE;

-- +goose StatementEnd