-- +goose Up
-- +goose StatementBegin
ALTER TABLE tickets DROP CONSTRAINT chk_ticket_status;
ALTER TABLE tickets
    ADD COLUMN archived_at TIMESTAMPTZ NULL,
    ADD CONSTRAINT chk_ticket_status CHECK (
        status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS', 'DONE', 'CANCELED', 'ARCHIVED')
    );

ALTER TABLE ticket_status_history DROP CONSTRAINT chk_ticket_history_old_status;
ALTER TABLE ticket_status_history DROP CONSTRAINT chk_ticket_history_new_status;
ALTER TABLE ticket_status_history
    ADD CONSTRAINT chk_ticket_history_old_status CHECK (
        old_status IS NULL OR old_status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS', 'DONE', 'CANCELED', 'ARCHIVED')
    ),
    ADD CONSTRAINT chk_ticket_history_new_status CHECK (
        new_status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS', 'DONE', 'CANCELED', 'ARCHIVED')
    );

CREATE INDEX idx_tickets_retention_archive
    ON tickets (COALESCE(completed_at, canceled_at, updated_at))
    WHERE status IN ('DONE', 'CANCELED');
CREATE INDEX idx_tickets_retention_purge
    ON tickets (archived_at)
    WHERE status = 'ARCHIVED';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_tickets_retention_purge;
DROP INDEX IF EXISTS idx_tickets_retention_archive;

DELETE FROM tickets WHERE status = 'ARCHIVED';

ALTER TABLE ticket_status_history DROP CONSTRAINT chk_ticket_history_old_status;
ALTER TABLE ticket_status_history DROP CONSTRAINT chk_ticket_history_new_status;
ALTER TABLE ticket_status_history
    ADD CONSTRAINT chk_ticket_history_old_status CHECK (
        old_status IS NULL OR old_status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS', 'DONE', 'CANCELED')
    ),
    ADD CONSTRAINT chk_ticket_history_new_status CHECK (
        new_status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS', 'DONE', 'CANCELED')
    );

ALTER TABLE tickets DROP CONSTRAINT chk_ticket_status;
ALTER TABLE tickets
    DROP COLUMN archived_at,
    ADD CONSTRAINT chk_ticket_status CHECK (
        status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS', 'DONE', 'CANCELED')
    );
-- +goose StatementEnd
