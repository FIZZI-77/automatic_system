-- +goose Up
CREATE TABLE ticket_reports (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    department_id UUID NOT NULL,
    ticket_id UUID NOT NULL,
    author_user_id UUID NOT NULL,
    description TEXT NOT NULL CHECK (length(btrim(description)) BETWEEN 1 AND 4000),
    idempotency_key TEXT,
    completion_status TEXT NOT NULL DEFAULT 'NONE',
    completion_file_id UUID,
    completion_error TEXT,
    completion_attempts INTEGER NOT NULL DEFAULT 0,
    completion_compensation_attempts INTEGER NOT NULL DEFAULT 0,
    completion_deadline_at TIMESTAMPTZ,
    completion_updated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ticket_reports_pkey PRIMARY KEY (department_id, id),
    CONSTRAINT ticket_reports_ticket_fkey
        FOREIGN KEY (department_id, ticket_id)
        REFERENCES tickets(department_id, id) ON DELETE CASCADE,
    CONSTRAINT ticket_reports_completion_status_check CHECK (
        completion_status IN (
            'NONE',
            'PENDING',
            'COMPLETED',
            'FAILED',
            'COMPENSATING',
            'COMPENSATED'
        )
    )
);

CREATE TABLE ticket_report_files (
    department_id UUID NOT NULL,
    report_id UUID NOT NULL,
    file_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ticket_report_files_pkey PRIMARY KEY (department_id, report_id, file_id),
    CONSTRAINT ticket_report_files_report_fkey
        FOREIGN KEY (department_id, report_id)
        REFERENCES ticket_reports(department_id, id) ON DELETE CASCADE
);

CREATE INDEX ticket_reports_ticket_idx ON ticket_reports(ticket_id, created_at DESC);
CREATE UNIQUE INDEX ticket_reports_idempotency_uidx
    ON ticket_reports(department_id, author_user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX ticket_reports_completion_deadline_idx
    ON ticket_reports(completion_deadline_at)
    WHERE completion_status = 'PENDING';
CREATE UNIQUE INDEX ticket_report_files_file_uidx
    ON ticket_report_files(department_id, file_id);

CREATE TABLE completion_report_inbox (
    event_id UUID PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS ticket_report_files;
DROP TABLE IF EXISTS completion_report_inbox;
DROP TABLE IF EXISTS ticket_reports;
