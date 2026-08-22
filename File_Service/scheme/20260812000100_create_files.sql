-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE files (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL,
    resource_type VARCHAR(64),
    resource_id UUID,
    name VARCHAR(255) NOT NULL,
    content_type VARCHAR(127) NOT NULL,
    size BIGINT NOT NULL CHECK (size > 0),
    checksum VARCHAR(128) NOT NULL,
    object_key VARCHAR(512) NOT NULL UNIQUE,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_UPLOAD'
        CHECK (status IN ('PENDING_UPLOAD','UPLOADED','LINKED','DELETED','QUARANTINED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    CHECK ((resource_type IS NULL) = (resource_id IS NULL))
);

CREATE INDEX files_owner_idx ON files(owner_user_id, created_at DESC) WHERE status <> 'DELETED';
CREATE INDEX files_resource_idx ON files(resource_type, resource_id, created_at) WHERE status = 'LINKED';

-- +goose Down
DROP TABLE IF EXISTS files;
