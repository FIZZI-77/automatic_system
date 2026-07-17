-- +goose Up
-- +goose StatementBegin

CREATE UNIQUE INDEX user_profiles_user_id_uidx ON user_profiles(user_id);
CREATE INDEX user_profiles_full_name_idx ON user_profiles(lower(full_name));
CREATE INDEX user_profiles_phone_idx ON user_profiles(phone) WHERE phone IS NOT NULL;
CREATE INDEX user_profiles_avatar_file_id_idx ON user_profiles(avatar_file_id) WHERE avatar_file_id IS NOT NULL;
CREATE INDEX user_profiles_created_at_idx ON user_profiles(created_at);
CREATE INDEX user_profiles_updated_at_idx ON user_profiles(updated_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS user_profiles_updated_at_idx;
DROP INDEX IF EXISTS user_profiles_created_at_idx;
DROP INDEX IF EXISTS user_profiles_avatar_file_id_idx;
DROP INDEX IF EXISTS user_profiles_phone_idx;
DROP INDEX IF EXISTS user_profiles_full_name_idx;
DROP INDEX IF EXISTS user_profiles_user_id_uidx;

-- +goose StatementEnd
