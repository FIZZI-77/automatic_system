-- +goose Up
-- +goose StatementBegin
CREATE INDEX reports_requested_created_idx
    ON reports(requested_by, created_at DESC);
CREATE INDEX reports_pending_idx
    ON reports(created_at)
    WHERE status = 'PENDING';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX reports_pending_idx;
DROP INDEX reports_requested_created_idx;
-- +goose StatementEnd
