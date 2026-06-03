-- +goose Up
-- +goose StatementBegin

CREATE INDEX brigades_department_id_idx ON brigades(department_id);
CREATE INDEX brigades_status_idx ON brigades(status);
CREATE INDEX brigades_created_at_idx ON brigades(created_at);
CREATE INDEX brigades_updated_at_idx ON brigades(updated_at);
CREATE UNIQUE INDEX brigades_department_name_active_uidx
    ON brigades(department_id, lower(name))
    WHERE status <> 'ARCHIVED';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS brigades_department_name_active_uidx;
DROP INDEX IF EXISTS brigades_updated_at_idx;
DROP INDEX IF EXISTS brigades_created_at_idx;
DROP INDEX IF EXISTS brigades_status_idx;
DROP INDEX IF EXISTS brigades_department_id_idx;

-- +goose StatementEnd
