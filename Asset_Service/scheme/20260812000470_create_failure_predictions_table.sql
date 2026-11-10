-- +goose Up
CREATE TABLE IF NOT EXISTS failure_predictions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets,
    risk_score double precision NOT NULL,
    risk_level text NOT NULL,
    failure_probability_90d double precision NOT NULL,
    factors jsonb NOT NULL,
    recommended_action text NOT NULL,
    calculated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS failure_predictions;
