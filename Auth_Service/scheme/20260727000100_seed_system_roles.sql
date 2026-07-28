-- +goose Up
-- +goose StatementBegin

INSERT INTO roles (name, description)
VALUES
    ('user', 'Default role assigned to every registered user'),
    ('admin', 'System administrator with unrestricted service access'),
    ('dispatcher', 'Department dispatcher managing tickets and brigades'),
    ('hr', 'Human resources employee managing work profiles'),
    ('qualification_verifier', 'Employee allowed to verify professional certifications')
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description;

INSERT INTO user_roles (user_id, role_id)
SELECT users.id, roles.id
FROM users
CROSS JOIN roles
WHERE roles.name = 'user'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM roles
WHERE name IN ('user', 'admin', 'dispatcher', 'hr', 'qualification_verifier');

-- +goose StatementEnd
