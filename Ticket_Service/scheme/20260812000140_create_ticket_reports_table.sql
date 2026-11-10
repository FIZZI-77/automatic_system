-- +goose Up
-- +goose StatementBegin
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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE ticket_reports CASCADE;
-- +goose StatementEnd
