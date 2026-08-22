-- +goose Up
-- +goose StatementBegin

CREATE TABLE work_profile_skill_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    work_profile_id UUID NOT NULL REFERENCES work_profiles(id) ON DELETE CASCADE,
    skill_id UUID NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    source_id UUID NULL,
    proficiency_level VARCHAR(64) NULL,
    valid_until TIMESTAMPTZ NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ NULL,
    CONSTRAINT work_profile_skill_grants_source_type_check CHECK (
        source_type IN ('MANUAL', 'CERTIFICATION')
    ),
    CONSTRAINT work_profile_skill_grants_proficiency_level_check CHECK (
        proficiency_level IS NULL OR length(btrim(proficiency_level)) BETWEEN 1 AND 64
    ),
    CONSTRAINT work_profile_skill_grants_source_id_check CHECK (
        (source_type = 'CERTIFICATION' AND source_id IS NOT NULL)
        OR source_type = 'MANUAL'
    ),
    CONSTRAINT work_profile_skill_grants_revoked_at_check CHECK (
        active = true OR revoked_at IS NOT NULL
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE work_profile_skill_grants CASCADE;

-- +goose StatementEnd
