-- +goose Up
CREATE TABLE IF NOT EXISTS asset_incidents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets,
    ticket_id uuid,
    failure_type text NOT NULL,
    description text NOT NULL,
    source text NOT NULL,
    priority text NOT NULL,
    repeated bool NOT NULL DEFAULT false,
    occurred_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS asset_incidents;
