-- +goose Up
CREATE TABLE IF NOT EXISTS asset_repairs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets,
    incident_id uuid,
    ticket_id uuid,
    brigade_id uuid,
    description text NOT NULL,
    replaced_components text NOT NULL,
    duration_minutes int NOT NULL,
    completed_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS asset_repairs;
