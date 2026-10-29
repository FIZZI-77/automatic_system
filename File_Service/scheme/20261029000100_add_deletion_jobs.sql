-- +goose Up
ALTER TABLE files ADD COLUMN upload_expires_at TIMESTAMPTZ;
CREATE TABLE file_deletion_jobs (
    file_id UUID PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX file_deletion_jobs_ready_idx ON file_deletion_jobs(not_before, file_id);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM file_deletion_jobs) THEN
        RAISE EXCEPTION 'finish pending file deletions before rolling back this migration';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE file_deletion_jobs;
ALTER TABLE files DROP COLUMN upload_expires_at;
