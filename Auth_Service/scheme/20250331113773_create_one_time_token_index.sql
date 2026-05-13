-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_one_time_tokens_user_id ON one_time_tokens(user_id);
CREATE INDEX idx_one_time_tokens_type ON one_time_tokens(type);
CREATE INDEX idx_one_time_tokens_expires_at ON one_time_tokens(expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_one_time_tokens_user_id;
DROP INDEX idx_one_time_tokens_type;
DROP INDEX idx_one_time_tokens_expires_at;
-- +goose StatementEnd