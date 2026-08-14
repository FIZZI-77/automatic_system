-- +goose Up
CREATE TABLE ticket_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_user_id UUID NOT NULL,
    description TEXT NOT NULL CHECK (length(btrim(description)) BETWEEN 1 AND 4000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ticket_report_files (
    report_id UUID NOT NULL REFERENCES ticket_reports(id) ON DELETE CASCADE,
    file_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(report_id, file_id)
);

CREATE INDEX ticket_reports_ticket_idx ON ticket_reports(ticket_id, created_at DESC);
CREATE UNIQUE INDEX ticket_report_files_file_uidx ON ticket_report_files(file_id);

-- +goose Down
DROP TABLE IF EXISTS ticket_report_files;
DROP TABLE IF EXISTS ticket_reports;
