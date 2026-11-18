-- +goose Up
ALTER TABLE dispatch_operations
    ADD COLUMN release_pending BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN release_actor_id UUID,
    ADD COLUMN assignment_comment TEXT NOT NULL DEFAULT '';

-- A terminal operation still owns its reservation until compensation finishes.
DROP INDEX dispatch_one_open_ticket_idx;
CREATE UNIQUE INDEX dispatch_one_open_ticket_idx ON dispatch_operations(ticket_id)
    WHERE status IN ('PENDING','RESERVED','CONFIRMING') OR release_pending;
DROP INDEX dispatch_one_reserved_brigade_idx;
CREATE UNIQUE INDEX dispatch_one_reserved_brigade_idx ON dispatch_operations(brigade_id)
    WHERE status IN ('RESERVED','CONFIRMING') OR release_pending;
CREATE INDEX dispatch_release_pending_idx ON dispatch_operations(updated_at, id)
    WHERE release_pending;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM dispatch_operations WHERE release_pending) THEN
        RAISE EXCEPTION 'finish pending brigade releases before rolling back this migration';
    END IF;
END $$;
-- +goose StatementEnd
DROP INDEX dispatch_release_pending_idx;
DROP INDEX dispatch_one_open_ticket_idx;
CREATE UNIQUE INDEX dispatch_one_open_ticket_idx ON dispatch_operations(ticket_id)
    WHERE status IN ('PENDING','RESERVED','CONFIRMING');
DROP INDEX dispatch_one_reserved_brigade_idx;
CREATE UNIQUE INDEX dispatch_one_reserved_brigade_idx ON dispatch_operations(brigade_id)
    WHERE status IN ('RESERVED','CONFIRMING');
ALTER TABLE dispatch_operations
    DROP COLUMN release_pending,
    DROP COLUMN release_actor_id,
    DROP COLUMN assignment_comment;
