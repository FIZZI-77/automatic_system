-- +goose Up
-- +goose StatementBegin

CREATE UNIQUE INDEX work_profiles_user_profile_id_uidx ON work_profiles(user_profile_id);
CREATE INDEX work_profiles_department_id_idx ON work_profiles(department_id);
CREATE INDEX work_profiles_department_status_idx ON work_profiles(department_id, status);
CREATE UNIQUE INDEX work_profiles_employee_number_uidx
    ON work_profiles(lower(employee_number))
    WHERE employee_number IS NOT NULL;
CREATE INDEX work_profiles_status_idx ON work_profiles(status);
CREATE INDEX work_profiles_position_idx ON work_profiles(lower(position));
CREATE INDEX work_profiles_created_at_idx ON work_profiles(created_at);
CREATE INDEX work_profiles_updated_at_idx ON work_profiles(updated_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS work_profiles_updated_at_idx;
DROP INDEX IF EXISTS work_profiles_created_at_idx;
DROP INDEX IF EXISTS work_profiles_position_idx;
DROP INDEX IF EXISTS work_profiles_status_idx;
DROP INDEX IF EXISTS work_profiles_employee_number_uidx;
DROP INDEX IF EXISTS work_profiles_department_status_idx;
DROP INDEX IF EXISTS work_profiles_department_id_idx;
DROP INDEX IF EXISTS work_profiles_user_profile_id_uidx;

-- +goose StatementEnd
