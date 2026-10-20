-- +goose Up

CREATE INDEX IF NOT EXISTS idx_tickets_incident_parts
    ON tickets(incident_id, status, department_id, created_at DESC)
    WHERE ticket_type = 'REQUEST' AND incident_id IS NOT NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_tickets_incident_parts;
