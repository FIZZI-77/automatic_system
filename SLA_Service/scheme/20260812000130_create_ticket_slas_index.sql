-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS ticket_slas_deadlines_idx
    ON ticket_slas(status, response_deadline, resolution_deadline);
CREATE INDEX IF NOT EXISTS ticket_slas_department_idx
    ON ticket_slas(department_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS ticket_slas_department_idx;
DROP INDEX IF EXISTS ticket_slas_deadlines_idx;
-- +goose StatementEnd
