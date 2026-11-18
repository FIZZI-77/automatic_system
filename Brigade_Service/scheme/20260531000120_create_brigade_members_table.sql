-- +goose Up
-- +goose StatementBegin
CREATE TABLE brigade_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brigade_id UUID NOT NULL REFERENCES brigades(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    profile_id UUID NULL,
    role VARCHAR(32) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    availability_status VARCHAR(32) NOT NULL DEFAULT 'AVAILABLE',
    availability_status_changed_at TIMESTAMP NOT NULL DEFAULT now(),
    joined_at TIMESTAMP NOT NULL DEFAULT now(),
    left_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT brigade_members_role_check CHECK (
        role IN ('LEAD', 'DRIVER', 'TECHNICIAN', 'TRAINEE')
    ),
    CONSTRAINT brigade_members_availability_status_check CHECK (
        availability_status IN ('AVAILABLE', 'UNAVAILABLE')
    )
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE brigade_members CASCADE;
-- +goose StatementEnd
