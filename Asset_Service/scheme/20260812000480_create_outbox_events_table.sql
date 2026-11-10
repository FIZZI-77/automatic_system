-- +goose Up
CREATE TABLE IF NOT EXISTS outbox_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'PENDING',
    attempts int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_at timestamptz,
    sent_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS outbox_events;
