-- +goose Up
-- +goose StatementBegin
CREATE INDEX idx_tickets_incident_requests
    ON tickets(department_id, incident_id, created_at DESC)
    WHERE ticket_type = 'REQUEST' AND incident_id IS NOT NULL;
CREATE INDEX idx_tickets_incident_deduplication
    ON tickets(department_id, category_id, created_at DESC)
    WHERE ticket_type = 'INCIDENT'
      AND status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS');
CREATE UNIQUE INDEX idx_tickets_external_request
    ON tickets(department_id, external_system_id, external_id)
    WHERE external_system_id IS NOT NULL AND external_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_tickets_external_request;
DROP INDEX idx_tickets_incident_deduplication;
DROP INDEX idx_tickets_incident_requests;
-- +goose StatementEnd
