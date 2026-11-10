-- +goose Up
-- +goose StatementBegin
CREATE UNIQUE INDEX brigade_shifts_one_active_idx
    ON brigade_shifts(brigade_id)
    WHERE ended_at IS NULL;
CREATE INDEX brigade_shifts_department_started_idx
    ON brigade_shifts(department_id, started_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS brigade_shifts_department_started_idx;
DROP INDEX IF EXISTS brigade_shifts_one_active_idx;
-- +goose StatementEnd
