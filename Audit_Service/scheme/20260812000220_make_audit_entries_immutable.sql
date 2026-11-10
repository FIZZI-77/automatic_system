-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_entries_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit entries are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_entries_no_update
    BEFORE UPDATE OR DELETE ON audit_entries
    FOR EACH ROW
    EXECUTE FUNCTION audit_entries_immutable();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER audit_entries_no_update ON audit_entries;
DROP FUNCTION audit_entries_immutable();
-- +goose StatementEnd
