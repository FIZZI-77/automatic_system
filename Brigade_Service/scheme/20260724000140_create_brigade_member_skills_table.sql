-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS brigade_member_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brigade_id UUID NOT NULL REFERENCES brigades(id) ON DELETE CASCADE,
    member_id UUID NOT NULL REFERENCES brigade_members(id) ON DELETE CASCADE,
    work_profile_id UUID NOT NULL,
    skill_id UUID NOT NULL,
    source_grant_id UUID NOT NULL,
    proficiency_level VARCHAR(100) NULL,
    valid_until TIMESTAMPTZ NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    work_profile_active BOOLEAN NOT NULL DEFAULT true,
    source_occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (member_id, source_grant_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS brigade_member_skills CASCADE;
-- +goose StatementEnd
