-- +goose Up
-- +goose StatementBegin
ALTER TABLE tickets
    ADD COLUMN ticket_type VARCHAR(50) NOT NULL DEFAULT 'INCIDENT',
    ADD COLUMN incident_id UUID NULL,
    ADD COLUMN external_system_id UUID NULL,
    ADD COLUMN external_id VARCHAR(255) NULL;

ALTER TABLE tickets
    ADD CONSTRAINT chk_ticket_type
        CHECK (ticket_type IN ('INCIDENT', 'REQUEST'));

ALTER TABLE tickets
    ADD CONSTRAINT chk_ticket_incident_relation
        CHECK (
            (ticket_type = 'INCIDENT' AND incident_id IS NULL)
            OR ticket_type = 'REQUEST'
        );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tickets
    DROP CONSTRAINT chk_ticket_incident_relation;
ALTER TABLE tickets
    DROP CONSTRAINT chk_ticket_type;
ALTER TABLE tickets
    DROP COLUMN external_id,
    DROP COLUMN external_system_id,
    DROP COLUMN incident_id,
    DROP COLUMN ticket_type;
-- +goose StatementEnd
