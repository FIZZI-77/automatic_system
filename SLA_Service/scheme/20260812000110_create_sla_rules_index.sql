-- +goose Up
-- +goose StatementBegin
CREATE UNIQUE INDEX sla_rules_scope_unique
    ON sla_rules(
        COALESCE(department_id, '00000000-0000-0000-0000-000000000000'),
        COALESCE(category_id, '00000000-0000-0000-0000-000000000000'),
        COALESCE(priority, '*')
    )
    WHERE active;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX sla_rules_scope_unique;
-- +goose StatementEnd
