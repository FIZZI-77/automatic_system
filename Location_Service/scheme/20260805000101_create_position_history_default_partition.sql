-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS position_history_default
    PARTITION OF position_history DEFAULT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS position_history_default;
-- +goose StatementEnd
