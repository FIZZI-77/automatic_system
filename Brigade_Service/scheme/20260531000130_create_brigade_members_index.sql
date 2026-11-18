-- +goose Up
-- +goose StatementBegin
CREATE INDEX brigade_members_brigade_id_idx ON brigade_members(brigade_id);
CREATE INDEX brigade_members_user_id_idx ON brigade_members(user_id);
CREATE INDEX brigade_members_profile_id_idx ON brigade_members(profile_id);
CREATE INDEX brigade_members_role_idx ON brigade_members(role);
CREATE INDEX brigade_members_availability_status_idx ON brigade_members(availability_status);
CREATE UNIQUE INDEX brigade_members_active_user_uidx
    ON brigade_members(brigade_id, user_id)
    WHERE active = true;
CREATE UNIQUE INDEX brigade_members_active_profile_uidx
    ON brigade_members(brigade_id, profile_id)
    WHERE active = true AND profile_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS brigade_members_active_profile_uidx;
DROP INDEX IF EXISTS brigade_members_active_user_uidx;
DROP INDEX IF EXISTS brigade_members_availability_status_idx;
DROP INDEX IF EXISTS brigade_members_role_idx;
DROP INDEX IF EXISTS brigade_members_profile_id_idx;
DROP INDEX IF EXISTS brigade_members_user_id_idx;
DROP INDEX IF EXISTS brigade_members_brigade_id_idx;
-- +goose StatementEnd
