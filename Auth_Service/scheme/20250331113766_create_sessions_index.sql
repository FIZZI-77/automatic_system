-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_client_id ON sessions(client_id);
CREATE INDEX idx_sessions_is_revoked ON sessions(is_revoked);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_sessions_user_id;
DROP INDEX idx_sessions_client_id;
DROP INDEX idx_sessions_is_revoked;
DROP INDEX idx_sessions_expires_at;

-- +goose StatementEnd