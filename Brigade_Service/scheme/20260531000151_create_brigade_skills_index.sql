-- +goose Up
-- +goose StatementBegin
CREATE INDEX brigade_skills_brigade_id_idx ON brigade_skills(brigade_id);
CREATE INDEX brigade_skills_skill_id_idx ON brigade_skills(skill_id);
CREATE UNIQUE INDEX brigade_skills_active_uidx
    ON brigade_skills(brigade_id, skill_id)
    WHERE active = true;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS brigade_skills_active_uidx;
DROP INDEX IF EXISTS brigade_skills_skill_id_idx;
DROP INDEX IF EXISTS brigade_skills_brigade_id_idx;
-- +goose StatementEnd
