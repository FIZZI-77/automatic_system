-- +goose Up
-- +goose StatementBegin

CREATE INDEX idempotency_keys_expires_at_idx ON idempotency_keys(expires_at);
CREATE INDEX idempotency_keys_status_idx ON idempotency_keys(status);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idempotency_keys_status_idx;
DROP INDEX IF EXISTS idempotency_keys_expires_at_idx;

-- +goose StatementEnd
