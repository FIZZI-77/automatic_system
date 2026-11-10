-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS files_owner_idx
    ON files(owner_user_id, created_at DESC)
    WHERE status <> 'DELETED';
CREATE INDEX IF NOT EXISTS files_resource_idx
    ON files(resource_type, resource_id, created_at)
    WHERE status = 'LINKED';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS files_resource_idx;
DROP INDEX IF EXISTS files_owner_idx;
-- +goose StatementEnd
