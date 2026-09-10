-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_tickets_department_created_at ON tickets(department_id, created_at DESC);
CREATE INDEX idx_tickets_department_status_created_at ON tickets(department_id, status, created_at DESC);
CREATE INDEX idx_tickets_user_created_at ON tickets(user_id, created_at DESC);
CREATE INDEX idx_tickets_brigade_created_at ON tickets(brigade_id, created_at DESC) WHERE brigade_id IS NOT NULL;
CREATE UNIQUE INDEX uq_tickets_department_active_brigade
    ON tickets(department_id, brigade_id)
    WHERE brigade_id IS NOT NULL AND status IN ('ASSIGNED', 'IN_PROGRESS');
CREATE INDEX tickets_asset_id_idx ON tickets(asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX idx_tickets_retention_archive
    ON tickets (COALESCE(completed_at, canceled_at, updated_at))
    WHERE status IN ('DONE', 'CANCELED');
CREATE INDEX idx_tickets_retention_purge
    ON tickets (archived_at)
    WHERE status = 'ARCHIVED';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_tickets_department_created_at;
DROP INDEX idx_tickets_department_status_created_at;
DROP INDEX idx_tickets_user_created_at;
DROP INDEX idx_tickets_brigade_created_at;
DROP INDEX uq_tickets_department_active_brigade;
DROP INDEX tickets_asset_id_idx;
DROP INDEX idx_tickets_retention_archive;
DROP INDEX idx_tickets_retention_purge;

-- +goose StatementEnd
