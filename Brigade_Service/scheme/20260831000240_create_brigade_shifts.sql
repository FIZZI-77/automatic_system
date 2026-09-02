-- +goose Up
CREATE TABLE brigade_shifts (
    id UUID PRIMARY KEY,
    brigade_id UUID NOT NULL REFERENCES brigades(id),
    department_id UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ NULL,
    started_by_user_id UUID NULL,
    ended_by_user_id UUID NULL,
    start_reason TEXT NOT NULL DEFAULT '',
    end_reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT brigade_shifts_time_check CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE UNIQUE INDEX brigade_shifts_one_active_idx
    ON brigade_shifts(brigade_id) WHERE ended_at IS NULL;
CREATE INDEX brigade_shifts_department_started_idx
    ON brigade_shifts(department_id, started_at DESC);

-- +goose Down
DROP TABLE brigade_shifts;
