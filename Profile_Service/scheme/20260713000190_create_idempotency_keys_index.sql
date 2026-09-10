-- +goose Up
-- +goose StatementBegin

CREATE UNIQUE INDEX idempotency_keys_actor_operation_key_uidx
    ON idempotency_keys(actor_key, operation, idempotency_key);
CREATE INDEX idempotency_keys_expires_at_idx ON idempotency_keys(expires_at);
CREATE INDEX idempotency_keys_status_idx ON idempotency_keys(status);
CREATE INDEX idempotency_keys_resource_idx
    ON idempotency_keys(resource_type, resource_id)
    WHERE resource_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idempotency_keys_resource_idx;
DROP INDEX IF EXISTS idempotency_keys_status_idx;
DROP INDEX IF EXISTS idempotency_keys_expires_at_idx;
DROP INDEX IF EXISTS idempotency_keys_actor_operation_key_uidx;

-- +goose StatementEnd
