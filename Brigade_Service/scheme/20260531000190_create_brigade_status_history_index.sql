-- +goose Up
-- +goose StatementBegin

CREATE INDEX brigade_status_history_brigade_id_idx ON brigade_status_history(brigade_id);
CREATE INDEX brigade_status_history_to_status_idx ON brigade_status_history(to_status);
CREATE INDEX brigade_status_history_created_at_idx ON brigade_status_history(created_at);
CREATE INDEX brigade_status_history_request_id_idx ON brigade_status_history(request_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS brigade_status_history_request_id_idx;
DROP INDEX IF EXISTS brigade_status_history_created_at_idx;
DROP INDEX IF EXISTS brigade_status_history_to_status_idx;
DROP INDEX IF EXISTS brigade_status_history_brigade_id_idx;

-- +goose StatementEnd
