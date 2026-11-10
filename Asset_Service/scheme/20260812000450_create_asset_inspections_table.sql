-- +goose Up
CREATE TABLE asset_inspections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets,
    inspector_user_id uuid NOT NULL,
    kind text NOT NULL,
    result text NOT NULL,
    defect_found bool NOT NULL,
    condition_score double precision NOT NULL,
    recommendation text NOT NULL,
    inspected_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE asset_inspections;
