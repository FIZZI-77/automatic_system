-- +goose Up
-- +goose StatementBegin


CREATE INDEX idx_signing_keys_is_active ON signing_keys(is_active);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_signing_keys_is_active;
-- +goose StatementEnd