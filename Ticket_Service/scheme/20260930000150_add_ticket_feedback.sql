-- +goose Up
ALTER TABLE tickets
    ADD COLUMN feedback_rating SMALLINT CHECK (feedback_rating BETWEEN 1 AND 5),
    ADD COLUMN feedback_resolved BOOLEAN,
    ADD COLUMN feedback_comment TEXT CHECK (feedback_comment IS NULL OR length(feedback_comment) <= 1000),
    ADD COLUMN feedback_created_at TIMESTAMPTZ,
    ADD COLUMN feedback_updated_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE tickets
    DROP COLUMN feedback_updated_at,
    DROP COLUMN feedback_created_at,
    DROP COLUMN feedback_comment,
    DROP COLUMN feedback_resolved,
    DROP COLUMN feedback_rating;
