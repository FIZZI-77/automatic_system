-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_entries_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit entries are immutable';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'audit_entries'::regclass
          AND tgname = 'audit_entries_no_update'
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER audit_entries_no_update
            BEFORE UPDATE OR DELETE ON audit_entries
            FOR EACH ROW
            EXECUTE FUNCTION audit_entries_immutable();
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS audit_entries_no_update ON audit_entries;
DROP FUNCTION IF EXISTS audit_entries_immutable();
-- +goose StatementEnd
