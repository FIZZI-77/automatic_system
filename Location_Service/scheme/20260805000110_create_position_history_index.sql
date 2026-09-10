-- +goose Up
-- +goose StatementBegin

CREATE UNIQUE INDEX position_history_event_id_uidx ON position_history(recorded_at, event_id);
CREATE UNIQUE INDEX position_history_device_sequence_uidx ON position_history(recorded_at, device_id, sequence);
CREATE INDEX position_history_brigade_recorded_at_idx ON position_history(brigade_id, recorded_at DESC);
CREATE INDEX position_history_vehicle_recorded_at_idx ON position_history(vehicle_id, recorded_at DESC);
CREATE INDEX position_history_device_recorded_at_idx ON position_history(device_id, recorded_at DESC);
CREATE INDEX position_history_received_at_idx ON position_history(received_at DESC);
CREATE INDEX position_history_position_gix ON position_history USING GIST(position);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS position_history_position_gix;
DROP INDEX IF EXISTS position_history_received_at_idx;
DROP INDEX IF EXISTS position_history_device_recorded_at_idx;
DROP INDEX IF EXISTS position_history_vehicle_recorded_at_idx;
DROP INDEX IF EXISTS position_history_brigade_recorded_at_idx;
DROP INDEX IF EXISTS position_history_device_sequence_uidx;
DROP INDEX IF EXISTS position_history_event_id_uidx;

-- +goose StatementEnd
