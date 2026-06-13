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

CREATE INDEX brigade_member_history_brigade_id_idx ON brigade_member_history(brigade_id);
CREATE INDEX brigade_member_history_member_id_idx ON brigade_member_history(member_id);
CREATE INDEX brigade_member_history_user_id_idx ON brigade_member_history(user_id);
CREATE INDEX brigade_member_history_created_at_idx ON brigade_member_history(created_at);
CREATE INDEX brigade_member_history_request_id_idx ON brigade_member_history(request_id);

CREATE INDEX brigade_member_status_history_brigade_id_idx ON brigade_member_status_history(brigade_id);
CREATE INDEX brigade_member_status_history_member_id_idx ON brigade_member_status_history(member_id);
CREATE INDEX brigade_member_status_history_user_id_idx ON brigade_member_status_history(user_id);
CREATE INDEX brigade_member_status_history_to_status_idx ON brigade_member_status_history(to_status);
CREATE INDEX brigade_member_status_history_created_at_idx ON brigade_member_status_history(created_at);
CREATE INDEX brigade_member_status_history_request_id_idx ON brigade_member_status_history(request_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS brigade_member_status_history_request_id_idx;
DROP INDEX IF EXISTS brigade_member_status_history_created_at_idx;
DROP INDEX IF EXISTS brigade_member_status_history_to_status_idx;
DROP INDEX IF EXISTS brigade_member_status_history_user_id_idx;
DROP INDEX IF EXISTS brigade_member_status_history_member_id_idx;
DROP INDEX IF EXISTS brigade_member_status_history_brigade_id_idx;
DROP INDEX IF EXISTS brigade_member_history_request_id_idx;
DROP INDEX IF EXISTS brigade_member_history_created_at_idx;
DROP INDEX IF EXISTS brigade_member_history_user_id_idx;
DROP INDEX IF EXISTS brigade_member_history_member_id_idx;
DROP INDEX IF EXISTS brigade_member_history_brigade_id_idx;
DROP INDEX IF EXISTS brigade_members_active_profile_uidx;
DROP INDEX IF EXISTS brigade_members_active_user_uidx;
DROP INDEX IF EXISTS brigade_members_availability_status_idx;
DROP INDEX IF EXISTS brigade_members_role_idx;
DROP INDEX IF EXISTS brigade_members_profile_id_idx;
DROP INDEX IF EXISTS brigade_members_user_id_idx;
DROP INDEX IF EXISTS brigade_members_brigade_id_idx;

-- +goose StatementEnd
