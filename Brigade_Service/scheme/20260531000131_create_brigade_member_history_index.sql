-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS brigade_member_history_brigade_id_idx ON brigade_member_history(brigade_id);
CREATE INDEX IF NOT EXISTS brigade_member_history_member_id_idx ON brigade_member_history(member_id);
CREATE INDEX IF NOT EXISTS brigade_member_history_user_id_idx ON brigade_member_history(user_id);
CREATE INDEX IF NOT EXISTS brigade_member_history_created_at_idx ON brigade_member_history(created_at);
CREATE INDEX IF NOT EXISTS brigade_member_history_request_id_idx ON brigade_member_history(request_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS brigade_member_history_request_id_idx;
DROP INDEX IF EXISTS brigade_member_history_created_at_idx;
DROP INDEX IF EXISTS brigade_member_history_user_id_idx;
DROP INDEX IF EXISTS brigade_member_history_member_id_idx;
DROP INDEX IF EXISTS brigade_member_history_brigade_id_idx;
-- +goose StatementEnd
