-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS devices_user_idx
    ON devices(user_id)
    WHERE active;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS devices_user_idx;
-- +goose StatementEnd
