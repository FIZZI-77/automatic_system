-- +goose Up
-- +goose StatementBegin


CREATE TABLE ticket_categories (
                                   id UUID PRIMARY KEY,
                                   code VARCHAR(100) NOT NULL UNIQUE,
                                   name VARCHAR(255) NOT NULL,
                                   description TEXT NULL,
                                   is_active BOOLEAN NOT NULL DEFAULT true,
                                   created_at TIMESTAMP NOT NULL DEFAULT now(),
                                   updated_at TIMESTAMP NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE ticket_categories CASCADE;

-- +goose StatementEnd