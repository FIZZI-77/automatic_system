-- +goose Up
-- +goose StatementBegin

CREATE INDEX work_profile_certifications_work_profile_id_idx ON work_profile_certifications(work_profile_id);
CREATE INDEX work_profile_certifications_type_id_idx ON work_profile_certifications(certification_type_id);
CREATE INDEX work_profile_certifications_status_idx ON work_profile_certifications(status);
CREATE INDEX work_profile_certifications_expires_at_idx ON work_profile_certifications(expires_at);
CREATE INDEX work_profile_certifications_file_id_idx ON work_profile_certifications(certificate_file_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS work_profile_certifications_file_id_idx;
DROP INDEX IF EXISTS work_profile_certifications_expires_at_idx;
DROP INDEX IF EXISTS work_profile_certifications_status_idx;
DROP INDEX IF EXISTS work_profile_certifications_type_id_idx;
DROP INDEX IF EXISTS work_profile_certifications_work_profile_id_idx;

-- +goose StatementEnd
