-- +goose Up
-- +goose StatementBegin
CREATE INDEX ticket_slas_deadlines_idx
    ON ticket_slas(status, response_deadline, resolution_deadline);
CREATE INDEX ticket_slas_department_idx
    ON ticket_slas(department_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX ticket_slas_department_idx;
DROP INDEX ticket_slas_deadlines_idx;
-- +goose StatementEnd
