-- +goose Up
-- +goose StatementBegin

CREATE TABLE inbox_events (
    event_id UUID PRIMARY KEY,
    source_service VARCHAR(100) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    partition_id INTEGER NOT NULL,
    message_offset BIGINT NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    event_version INTEGER NOT NULL DEFAULT 1,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (topic, partition_id, message_offset)
);

CREATE INDEX inbox_events_processed_at_idx ON inbox_events(processed_at);
CREATE INDEX inbox_events_type_idx ON inbox_events(event_type);

CREATE TABLE brigade_member_skills (
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

CREATE INDEX brigade_member_skills_brigade_idx
    ON brigade_member_skills(brigade_id, skill_id)
    WHERE active = true;
CREATE INDEX brigade_member_skills_profile_idx
    ON brigade_member_skills(work_profile_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS brigade_member_skills CASCADE;
DROP TABLE IF EXISTS inbox_events CASCADE;

-- +goose StatementEnd
