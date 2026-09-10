-- +goose Up
-- +goose StatementBegin



CREATE TABLE one_time_tokens (
                                 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                 token_hash TEXT NOT NULL UNIQUE,
                                 type VARCHAR(64) NOT NULL,
                                 expires_at TIMESTAMPTZ NOT NULL,
                                 used_at TIMESTAMPTZ,
                                 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE one_time_tokens CASCADE;

-- +goose StatementEnd