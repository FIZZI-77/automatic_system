-- +goose Up
-- +goose StatementBegin


CREATE TABLE ticket_status_history (
                                       id UUID NOT NULL,
                                       department_id UUID NOT NULL,

                                       ticket_id UUID NOT NULL,

                                       old_status VARCHAR(50) NULL,
                                       new_status VARCHAR(50) NOT NULL,

                                       changed_by UUID NULL,
                                       comment TEXT NULL,

                                       created_at TIMESTAMP NOT NULL DEFAULT now(),

                                       CONSTRAINT ticket_status_history_pkey PRIMARY KEY (department_id, id),
                                       CONSTRAINT ticket_status_history_ticket_fkey
                                           FOREIGN KEY (department_id, ticket_id)
                                           REFERENCES tickets(department_id, id) ON DELETE CASCADE,

                                       CONSTRAINT chk_ticket_history_old_status CHECK (
                                           old_status IS NULL OR old_status IN (
                                                                                'NEW',
                                                                                'ASSIGNED',
                                                                                'IN_PROGRESS',
                                                                                'DONE',
                                                                                'CANCELED',
                                                                                'ARCHIVED'
                                               )
                                           ),

                                       CONSTRAINT chk_ticket_history_new_status CHECK (
                                           new_status IN (
                                                          'NEW',
                                                          'ASSIGNED',
                                                          'IN_PROGRESS',
                                                          'DONE',
                                                          'CANCELED',
                                                          'ARCHIVED'
                                               )
                                           )
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE ticket_status_history CASCADE;

-- +goose StatementEnd
