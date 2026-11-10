-- +goose Up
-- +goose StatementBegin
CREATE UNIQUE INDEX IF NOT EXISTS ticket_report_files_file_uidx
    ON ticket_report_files(department_id, file_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS ticket_report_files_file_uidx;
-- +goose StatementEnd
