-- +goose Up
ALTER TABLE dispatch_operations ADD COLUMN trigger_event_id UUID;
CREATE UNIQUE INDEX dispatch_trigger_event_id_idx ON dispatch_operations(trigger_event_id)
    WHERE trigger_event_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS dispatch_trigger_event_id_idx;
ALTER TABLE dispatch_operations DROP COLUMN IF EXISTS trigger_event_id;
