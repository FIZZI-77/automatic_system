-- +goose Up
-- +goose StatementBegin
CREATE INDEX file_deletion_jobs_ready_idx
    ON file_deletion_jobs(not_before, file_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS file_deletion_jobs_ready_idx;
-- +goose StatementEnd
