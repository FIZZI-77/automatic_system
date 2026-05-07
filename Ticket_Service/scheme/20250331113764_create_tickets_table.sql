-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE tickets (
                         id UUID PRIMARY KEY,

                         department_id UUID NOT NULL,
                         user_id UUID NOT NULL,
                         brigade_id UUID NULL,

                         title VARCHAR(255) NOT NULL,
                         description TEXT NOT NULL,

                         category_id UUID NOT NULL REFERENCES ticket_categories(id),
                         priority VARCHAR(50) NOT NULL,
                         status VARCHAR(50) NOT NULL,

                         address TEXT NOT NULL,
                         latitude DOUBLE PRECISION NOT NULL,
                         longitude DOUBLE PRECISION NOT NULL,

                         created_at TIMESTAMP NOT NULL DEFAULT now(),
                         updated_at TIMESTAMP NOT NULL DEFAULT now(),
                         assigned_at TIMESTAMP NULL,
                         completed_at TIMESTAMP NULL,
                         canceled_at TIMESTAMP NULL

                         CONSTRAINT chk_ticket_status CHECK (
                                status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS', 'DONE', 'CANCELED')
                         ),

                         CONSTRAINT chk_ticket_priority CHECK (
                             priority IN ('LOW', 'MEDIUM', 'HIGH', 'EMERGENCY')
                         )
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE tickets CASCADE;

-- +goose StatementEnd