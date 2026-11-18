-- +goose Up
-- +goose StatementBegin
ALTER TABLE files ADD COLUMN upload_expires_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE files DROP COLUMN upload_expires_at;
-- +goose StatementEnd
