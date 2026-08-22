-- +goose Up
-- +goose StatementBegin

CREATE TABLE certification_type_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    certification_type_id UUID NOT NULL REFERENCES certification_types(id) ON DELETE CASCADE,
    skill_id UUID NOT NULL,
    proficiency_level VARCHAR(64) NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT certification_type_skills_proficiency_level_check CHECK (
        proficiency_level IS NULL OR length(btrim(proficiency_level)) BETWEEN 1 AND 64
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE certification_type_skills CASCADE;

-- +goose StatementEnd
