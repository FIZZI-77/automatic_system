-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS ticket_reports_ticket_idx
    ON ticket_reports(ticket_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ticket_reports_idempotency_uidx
    ON ticket_reports(department_id, author_user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ticket_reports_completion_deadline_idx
    ON ticket_reports(completion_deadline_at)
    WHERE completion_status = 'PENDING';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS ticket_reports_completion_deadline_idx;
DROP INDEX IF EXISTS ticket_reports_idempotency_uidx;
DROP INDEX IF EXISTS ticket_reports_ticket_idx;
-- +goose StatementEnd
