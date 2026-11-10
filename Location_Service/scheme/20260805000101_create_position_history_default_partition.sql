-- +goose Up
-- +goose StatementBegin
CREATE TABLE position_history_default
    PARTITION OF position_history DEFAULT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE position_history_default;
-- +goose StatementEnd
