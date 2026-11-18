-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS notifications_user_idx
    ON notifications(user_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS notifications_user_idx;
-- +goose StatementEnd
