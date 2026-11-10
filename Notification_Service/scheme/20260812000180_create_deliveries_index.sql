-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS deliveries_work_idx
    ON deliveries(status, next_attempt_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS deliveries_work_idx;
-- +goose StatementEnd
