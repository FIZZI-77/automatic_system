-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE outbox_events (
                               id UUID PRIMARY KEY,

                               aggregate_type VARCHAR(100) NOT NULL,
                               aggregate_id UUID NOT NULL,

                               event_type VARCHAR(100) NOT NULL,
                               payload JSONB NOT NULL,

                               status VARCHAR(50) NOT NULL DEFAULT 'PENDING',

                               attempts INT NOT NULL DEFAULT 0,
                               last_error TEXT NULL,
                               next_attempt_at TIMESTAMP NOT NULL DEFAULT now(),
                               locked_at TIMESTAMP NULL,

                               created_at TIMESTAMP NOT NULL DEFAULT now(),
                               sent_at TIMESTAMP NULL,

                               CONSTRAINT chk_outbox_status CHECK (
                                   status IN (
                                              'PENDING',
                                              'PROCESSING',
                                              'SENT',
                                              'FAILED'
                                       )
                                   )
);

CREATE INDEX outbox_events_retry_idx
    ON outbox_events(status, next_attempt_at, created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE outbox_events CASCADE;

-- +goose StatementEnd
