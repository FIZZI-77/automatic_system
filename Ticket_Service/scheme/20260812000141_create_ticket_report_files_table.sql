-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ticket_report_files (
    department_id UUID NOT NULL,
    report_id UUID NOT NULL,
    file_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ticket_report_files_pkey PRIMARY KEY (department_id, report_id, file_id),
    CONSTRAINT ticket_report_files_report_fkey
        FOREIGN KEY (department_id, report_id)
        REFERENCES ticket_reports(department_id, id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ticket_report_files CASCADE;
-- +goose StatementEnd
