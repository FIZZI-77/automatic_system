-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS brigade_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brigade_id UUID NOT NULL REFERENCES brigades(id) ON DELETE CASCADE,
    skill_id UUID NOT NULL REFERENCES skills(id) ON DELETE RESTRICT,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS brigade_skills CASCADE;
-- +goose StatementEnd
