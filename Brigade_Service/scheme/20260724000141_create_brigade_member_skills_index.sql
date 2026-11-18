-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS brigade_member_skills_brigade_idx
    ON brigade_member_skills(brigade_id, skill_id)
    WHERE active = true;
CREATE INDEX IF NOT EXISTS brigade_member_skills_profile_idx
    ON brigade_member_skills(work_profile_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS brigade_member_skills_profile_idx;
DROP INDEX IF EXISTS brigade_member_skills_brigade_idx;
-- +goose StatementEnd
