-- +goose Up

ALTER TABLE tickets
    ADD COLUMN ticket_type VARCHAR(50) NOT NULL DEFAULT 'INCIDENT',
    ADD COLUMN incident_id UUID NULL,
    ADD COLUMN external_system_id UUID NULL,
    ADD COLUMN external_id VARCHAR(255) NULL;

ALTER TABLE tickets
    ADD CONSTRAINT chk_ticket_type
        CHECK (ticket_type IN ('INCIDENT', 'REQUEST')),
    ADD CONSTRAINT chk_ticket_incident_relation
        CHECK (
            (ticket_type = 'INCIDENT' AND incident_id IS NULL)
            OR ticket_type = 'REQUEST'
        );

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

CREATE TABLE ticket_integrations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    secret_hash VARCHAR(128) NOT NULL,
    secret_prefix VARCHAR(16) NOT NULL,
    allowed_department_id UUID NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL,

    CONSTRAINT chk_ticket_integrations_client_id
        CHECK (client_id ~ '^[a-z0-9][a-z0-9_-]{2,99}$')
);

CREATE INDEX idx_ticket_integrations_active
    ON ticket_integrations(client_id)
    WHERE is_active = TRUE;

-- +goose Down

DROP TABLE ticket_integrations;

DROP INDEX idx_tickets_external_request;
DROP INDEX idx_tickets_incident_deduplication;
DROP INDEX idx_tickets_incident_requests;

ALTER TABLE tickets
    DROP CONSTRAINT chk_ticket_incident_relation,
    DROP CONSTRAINT chk_ticket_type,
    DROP COLUMN external_id,
    DROP COLUMN external_system_id,
    DROP COLUMN incident_id,
    DROP COLUMN ticket_type;
