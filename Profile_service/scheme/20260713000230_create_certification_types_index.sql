-- +goose Up
-- +goose StatementBegin

CREATE UNIQUE INDEX certification_types_code_uidx ON certification_types(lower(code));
CREATE INDEX certification_types_active_idx ON certification_types(active);
CREATE INDEX certification_types_created_at_idx ON certification_types(created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS certification_types_created_at_idx;
DROP INDEX IF EXISTS certification_types_active_idx;
DROP INDEX IF EXISTS certification_types_code_uidx;

-- +goose StatementEnd
