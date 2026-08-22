-- +goose Up
-- +goose StatementBegin

CREATE INDEX work_profile_skill_grants_work_profile_id_idx ON work_profile_skill_grants(work_profile_id);
CREATE INDEX work_profile_skill_grants_skill_id_idx ON work_profile_skill_grants(skill_id);
CREATE INDEX work_profile_skill_grants_active_idx ON work_profile_skill_grants(active);
CREATE INDEX work_profile_skill_grants_valid_until_idx ON work_profile_skill_grants(valid_until);
CREATE UNIQUE INDEX work_profile_skill_grants_active_source_uidx
    ON work_profile_skill_grants(work_profile_id, skill_id, source_type, source_id)
    WHERE active = true AND source_id IS NOT NULL;
CREATE UNIQUE INDEX work_profile_skill_grants_active_manual_uidx
    ON work_profile_skill_grants(work_profile_id, skill_id, source_type)
    WHERE active = true AND source_type = 'MANUAL' AND source_id IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS work_profile_skill_grants_active_manual_uidx;
DROP INDEX IF EXISTS work_profile_skill_grants_active_source_uidx;
DROP INDEX IF EXISTS work_profile_skill_grants_valid_until_idx;
DROP INDEX IF EXISTS work_profile_skill_grants_active_idx;
DROP INDEX IF EXISTS work_profile_skill_grants_skill_id_idx;
DROP INDEX IF EXISTS work_profile_skill_grants_work_profile_id_idx;

-- +goose StatementEnd
