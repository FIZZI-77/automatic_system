-- +goose Up
CREATE TABLE IF NOT EXISTS asset_status_history (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets,
    old_status text,
    new_status text NOT NULL,
    reason text NOT NULL,
    changed_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS asset_status_history;
