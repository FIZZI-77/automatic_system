-- +goose Up
-- +goose StatementBegin

ALTER TABLE outbox_events
    ADD COLUMN next_attempt_at TIMESTAMP NOT NULL DEFAULT now(),
    ADD COLUMN locked_at TIMESTAMP NULL;

CREATE INDEX outbox_events_retry_idx
    ON outbox_events(status, next_attempt_at, created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS outbox_events_retry_idx;

ALTER TABLE outbox_events
    DROP COLUMN locked_at,
    DROP COLUMN next_attempt_at;

-- +goose StatementEnd
