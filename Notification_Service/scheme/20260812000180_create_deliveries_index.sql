-- +goose Up
-- +goose StatementBegin
CREATE INDEX deliveries_work_idx
    ON deliveries(status, next_attempt_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX deliveries_work_idx;
-- +goose StatementEnd
