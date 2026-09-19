-- +goose Up
ALTER TABLE ticket_slas ADD COLUMN ticket_created_at timestamptz;
UPDATE ticket_slas SET ticket_created_at = created_at WHERE ticket_created_at IS NULL;
ALTER TABLE ticket_slas ALTER COLUMN ticket_created_at SET NOT NULL;

-- +goose Down
ALTER TABLE ticket_slas DROP COLUMN ticket_created_at;
