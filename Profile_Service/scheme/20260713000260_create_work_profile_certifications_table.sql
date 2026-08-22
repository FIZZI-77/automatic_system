-- +goose Up
-- +goose StatementBegin

CREATE TABLE work_profile_certifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    work_profile_id UUID NOT NULL REFERENCES work_profiles(id) ON DELETE CASCADE,
    certification_type_id UUID NOT NULL REFERENCES certification_types(id),
    certificate_number VARCHAR(128) NULL,
    issuer VARCHAR(255) NULL,
    issued_at DATE NULL,
    expires_at DATE NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    certificate_file_id UUID NULL,
    verified_by_user_id UUID NULL,
    verified_at TIMESTAMPTZ NULL,
    rejection_reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT work_profile_certifications_number_check CHECK (
        certificate_number IS NULL OR length(btrim(certificate_number)) BETWEEN 1 AND 128
    ),
    CONSTRAINT work_profile_certifications_issuer_check CHECK (
        issuer IS NULL OR length(btrim(issuer)) BETWEEN 1 AND 255
    ),
    CONSTRAINT work_profile_certifications_status_check CHECK (
        status IN ('PENDING', 'VERIFIED', 'REJECTED', 'EXPIRED', 'REVOKED')
    ),
    CONSTRAINT work_profile_certifications_dates_check CHECK (
        issued_at IS NULL OR expires_at IS NULL OR expires_at >= issued_at
    ),
    CONSTRAINT work_profile_certifications_verified_check CHECK (
        (status = 'VERIFIED' AND verified_by_user_id IS NOT NULL AND verified_at IS NOT NULL)
        OR status <> 'VERIFIED'
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE work_profile_certifications CASCADE;

-- +goose StatementEnd
