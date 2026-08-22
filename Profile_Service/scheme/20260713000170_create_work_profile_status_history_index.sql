-- +goose Up
-- +goose StatementBegin

CREATE INDEX work_profile_status_history_work_profile_id_idx
    ON work_profile_status_history(work_profile_id);
CREATE INDEX work_profile_status_history_profile_created_at_idx
    ON work_profile_status_history(work_profile_id, created_at DESC);
CREATE INDEX work_profile_status_history_to_status_idx
    ON work_profile_status_history(to_status);
CREATE INDEX work_profile_status_history_changed_by_user_id_idx
    ON work_profile_status_history(changed_by_user_id)
    WHERE changed_by_user_id IS NOT NULL;
CREATE INDEX work_profile_status_history_request_id_idx
    ON work_profile_status_history(request_id)
    WHERE request_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS work_profile_status_history_request_id_idx;
DROP INDEX IF EXISTS work_profile_status_history_changed_by_user_id_idx;
DROP INDEX IF EXISTS work_profile_status_history_to_status_idx;
DROP INDEX IF EXISTS work_profile_status_history_profile_created_at_idx;
DROP INDEX IF EXISTS work_profile_status_history_work_profile_id_idx;

-- +goose StatementEnd
