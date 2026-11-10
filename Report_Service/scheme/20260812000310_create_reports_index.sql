-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS reports_requested_created_idx
    ON reports(requested_by, created_at DESC);
CREATE INDEX IF NOT EXISTS reports_pending_idx
    ON reports(created_at)
    WHERE status = 'PENDING';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS reports_pending_idx;
DROP INDEX IF EXISTS reports_requested_created_idx;
-- +goose StatementEnd
