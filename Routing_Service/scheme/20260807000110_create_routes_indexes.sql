-- +goose Up
CREATE INDEX routes_ticket_id_idx
 ON routes(ticket_id, created_at DESC);

CREATE INDEX routes_brigade_id_idx
 ON routes(brigade_id, created_at DESC);

CREATE INDEX routes_status_idx
 ON routes(status, created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS routes_status_idx;
DROP INDEX IF EXISTS routes_brigade_id_idx;
DROP INDEX IF EXISTS routes_ticket_id_idx;
