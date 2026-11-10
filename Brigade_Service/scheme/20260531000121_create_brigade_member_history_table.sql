-- +goose Up
-- +goose StatementBegin
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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE brigade_member_history CASCADE;
-- +goose StatementEnd
