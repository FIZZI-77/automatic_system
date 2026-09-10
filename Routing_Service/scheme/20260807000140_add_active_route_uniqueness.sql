-- +goose Up
CREATE UNIQUE INDEX routes_one_open_route_per_ticket_idx
    ON routes(ticket_id)
    WHERE status IN ('PLANNED', 'ACTIVE');

-- +goose Down
DROP INDEX IF EXISTS routes_one_open_route_per_ticket_idx;
