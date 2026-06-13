-- +goose Up
-- +goose StatementBegin


CREATE TABLE ticket_status_history (
                                       id UUID PRIMARY KEY,

                                       ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,

                                       old_status VARCHAR(50) NULL,
                                       new_status VARCHAR(50) NOT NULL,

                                       changed_by UUID NULL,
                                       comment TEXT NULL,

                                       created_at TIMESTAMP NOT NULL DEFAULT now(),

                                       CONSTRAINT chk_ticket_history_old_status CHECK (
                                           old_status IS NULL OR old_status IN (
                                                                                'NEW',
                                                                                'ASSIGNED',
                                                                                'IN_PROGRESS',
                                                                                'DONE',
                                                                                'CANCELED'
                                               )
                                           ),

                                       CONSTRAINT chk_ticket_history_new_status CHECK (
                                           new_status IN (
                                                          'NEW',
                                                          'ASSIGNED',
                                                          'IN_PROGRESS',
                                                          'DONE',
                                                          'CANCELED'
                                               )
                                           )
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE ticket_status_history CASCADE;

-- +goose StatementEnd