-- +goose Up
-- +goose StatementBegin

CREATE INDEX certification_type_skills_type_id_idx ON certification_type_skills(certification_type_id);
CREATE INDEX certification_type_skills_skill_id_idx ON certification_type_skills(skill_id);
CREATE INDEX certification_type_skills_active_idx ON certification_type_skills(active);
CREATE UNIQUE INDEX certification_type_skills_active_uidx
    ON certification_type_skills(certification_type_id, skill_id)
    WHERE active = true;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS certification_type_skills_active_uidx;
DROP INDEX IF EXISTS certification_type_skills_active_idx;
DROP INDEX IF EXISTS certification_type_skills_skill_id_idx;
DROP INDEX IF EXISTS certification_type_skills_type_id_idx;

-- +goose StatementEnd
