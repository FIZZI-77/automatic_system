-- +goose Up
CREATE INDEX asset_incidents_history_idx ON asset_incidents (asset_id, occurred_at DESC, id DESC);
CREATE INDEX asset_incidents_ticket_idx ON asset_incidents (asset_id, ticket_id) WHERE ticket_id IS NOT NULL;
CREATE INDEX asset_incidents_failure_time_idx ON asset_incidents (asset_id, failure_type, occurred_at);

WITH previous AS (
    SELECT id, occurred_at, lag(occurred_at) OVER (
        PARTITION BY asset_id, failure_type ORDER BY occurred_at, id
    ) AS previous_at
    FROM asset_incidents
)
UPDATE asset_incidents AS incident
SET repeated = COALESCE(previous.previous_at > previous.occurred_at - interval '2160 hours', false)
FROM previous
WHERE incident.id = previous.id
  AND incident.repeated IS DISTINCT FROM COALESCE(previous.previous_at > previous.occurred_at - interval '2160 hours', false);

-- +goose Down
DROP INDEX asset_incidents_failure_time_idx;
DROP INDEX asset_incidents_ticket_idx;
DROP INDEX asset_incidents_history_idx;
