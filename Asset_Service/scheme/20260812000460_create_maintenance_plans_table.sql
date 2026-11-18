-- +goose Up
CREATE TABLE IF NOT EXISTS maintenance_plans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets,
    kind text NOT NULL,
    interval_days int NOT NULL,
    next_due_at timestamptz NOT NULL,
    active bool NOT NULL DEFAULT true,
    last_completed_at timestamptz,
    UNIQUE (asset_id, kind)
);

-- +goose Down
DROP TABLE IF EXISTS maintenance_plans;
