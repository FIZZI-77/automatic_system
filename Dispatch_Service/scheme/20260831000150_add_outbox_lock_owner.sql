-- +goose Up
ALTER TABLE dispatch_outbox_events ADD COLUMN locked_by UUID;

-- +goose Down
ALTER TABLE dispatch_outbox_events DROP COLUMN IF EXISTS locked_by;
