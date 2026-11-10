-- +goose Up
-- +goose StatementBegin
CREATE INDEX report_outbox_pending_idx
    ON outbox_events(next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'FAILED');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX report_outbox_pending_idx;
-- +goose StatementEnd
