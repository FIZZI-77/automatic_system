-- +goose Up
-- +goose StatementBegin

CREATE TABLE work_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_profile_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    department_id UUID NOT NULL,
    employee_number VARCHAR(64) NULL,
    position VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    deactivated_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT work_profiles_employee_number_not_blank_check CHECK (
        employee_number IS NULL OR length(btrim(employee_number)) BETWEEN 1 AND 64
    ),
    CONSTRAINT work_profiles_position_not_blank_check CHECK (
        length(btrim(position)) BETWEEN 2 AND 128
    ),
    CONSTRAINT work_profiles_status_check CHECK (
        status IN ('ACTIVE', 'INACTIVE', 'ON_SHIFT', 'OFF_SHIFT', 'SUSPENDED')
    ),
    CONSTRAINT work_profiles_deactivated_at_check CHECK (
        status = 'INACTIVE' OR deactivated_at IS NULL
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE work_profiles CASCADE;

-- +goose StatementEnd
