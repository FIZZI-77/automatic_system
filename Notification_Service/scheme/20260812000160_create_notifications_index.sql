-- +goose Up
-- +goose StatementBegin
CREATE INDEX notifications_user_idx
    ON notifications(user_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX notifications_user_idx;
-- +goose StatementEnd
