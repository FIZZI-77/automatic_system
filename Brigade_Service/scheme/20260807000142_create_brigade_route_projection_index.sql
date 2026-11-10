-- +goose Up
-- +goose StatementBegin
CREATE UNIQUE INDEX brigade_route_projection_route_id_idx
    ON brigade_route_projection(route_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS brigade_route_projection_route_id_idx;
-- +goose StatementEnd
