-- +goose Up
-- +goose StatementBegin

CREATE INDEX brigade_schedule_brigade_id_idx ON brigade_schedule(brigade_id);
CREATE INDEX brigade_schedule_day_of_week_idx ON brigade_schedule(day_of_week);
CREATE INDEX brigade_schedule_active_idx ON brigade_schedule(active);
CREATE INDEX brigade_schedule_valid_from_idx ON brigade_schedule(valid_from);
CREATE INDEX brigade_schedule_valid_to_idx ON brigade_schedule(valid_to);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS brigade_schedule_valid_to_idx;
DROP INDEX IF EXISTS brigade_schedule_valid_from_idx;
DROP INDEX IF EXISTS brigade_schedule_active_idx;
DROP INDEX IF EXISTS brigade_schedule_day_of_week_idx;
DROP INDEX IF EXISTS brigade_schedule_brigade_id_idx;

-- +goose StatementEnd
