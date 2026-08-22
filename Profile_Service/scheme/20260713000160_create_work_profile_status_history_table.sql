-- +goose Up
-- +goose StatementBegin

CREATE TABLE work_profile_status_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    work_profile_id UUID NOT NULL REFERENCES work_profiles(id) ON DELETE CASCADE,
    from_status VARCHAR(32) NULL,
    to_status VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    changed_by_user_id UUID NULL,
    request_id VARCHAR(128) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT work_profile_status_history_from_status_check CHECK (
        from_status IS NULL OR from_status IN (
            'ACTIVE', 'INACTIVE', 'ON_SHIFT', 'OFF_SHIFT', 'SUSPENDED'
        )
    ),
    CONSTRAINT work_profile_status_history_to_status_check CHECK (
        to_status IN ('ACTIVE', 'INACTIVE', 'ON_SHIFT', 'OFF_SHIFT', 'SUSPENDED')
    ),
    CONSTRAINT work_profile_status_history_transition_check CHECK (
        from_status IS NULL OR from_status <> to_status
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE work_profile_status_history CASCADE;

-- +goose StatementEnd
