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

CREATE TABLE brigade_member_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brigade_id UUID NOT NULL REFERENCES brigades(id) ON DELETE CASCADE,
    member_id UUID NULL REFERENCES brigade_members(id) ON DELETE SET NULL,
    user_id UUID NOT NULL,
    profile_id UUID NULL,
    action VARCHAR(32) NOT NULL,
    old_role VARCHAR(32) NULL,
    new_role VARCHAR(32) NULL,
    changed_by_user_id UUID NULL,
    request_id VARCHAR(128) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT brigade_member_history_action_check CHECK (
        action IN ('ADDED', 'REMOVED', 'ROLE_CHANGED')
    ),
    CONSTRAINT brigade_member_history_old_role_check CHECK (
        old_role IS NULL OR old_role IN ('LEAD', 'DRIVER', 'TECHNICIAN', 'TRAINEE')
    ),
    CONSTRAINT brigade_member_history_new_role_check CHECK (
        new_role IS NULL OR new_role IN ('LEAD', 'DRIVER', 'TECHNICIAN', 'TRAINEE')
    )
);

CREATE TABLE brigade_member_status_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brigade_id UUID NOT NULL REFERENCES brigades(id) ON DELETE CASCADE,
    member_id UUID NULL REFERENCES brigade_members(id) ON DELETE SET NULL,
    user_id UUID NOT NULL,
    from_status VARCHAR(32) NULL,
    to_status VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    changed_by_user_id UUID NULL,
    request_id VARCHAR(128) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT brigade_member_status_history_from_status_check CHECK (
        from_status IS NULL OR from_status IN ('AVAILABLE', 'UNAVAILABLE')
    ),
    CONSTRAINT brigade_member_status_history_to_status_check CHECK (
        to_status IN ('AVAILABLE', 'UNAVAILABLE')
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE brigade_member_status_history CASCADE;
DROP TABLE brigade_member_history CASCADE;
DROP TABLE brigade_members CASCADE;

-- +goose StatementEnd
