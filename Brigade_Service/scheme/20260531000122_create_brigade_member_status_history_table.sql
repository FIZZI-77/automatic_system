-- +goose Up
-- +goose StatementBegin
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
-- +goose StatementEnd
