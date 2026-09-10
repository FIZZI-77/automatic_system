-- +goose Up
-- +goose StatementBegin

INSERT INTO roles (name, description)
VALUES ('worker', 'Field worker assigned to a brigade and work profile')
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM roles WHERE name = 'worker';

-- +goose StatementEnd
