-- +goose Up
-- +goose StatementBegin
CREATE TABLE file_deletion_jobs (
    file_id UUID PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM file_deletion_jobs) THEN
        RAISE EXCEPTION 'finish pending file deletions before rolling back this migration';
    END IF;
END;
$$;

DROP TABLE file_deletion_jobs;
-- +goose StatementEnd
