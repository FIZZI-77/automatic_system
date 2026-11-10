-- +goose Up
-- +goose StatementBegin
CREATE UNIQUE INDEX skills_code_uidx ON skills(lower(code));
CREATE INDEX skills_active_idx ON skills(active);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS skills_active_idx;
DROP INDEX IF EXISTS skills_code_uidx;
-- +goose StatementEnd
