-- +goose Up
-- +goose StatementBegin

CREATE TABLE brigade_schedule (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brigade_id UUID NOT NULL REFERENCES brigades(id) ON DELETE CASCADE,
    day_of_week SMALLINT NOT NULL,
    starts_at TIME NOT NULL,
    ends_at TIME NOT NULL,
    timezone VARCHAR(64) NOT NULL DEFAULT 'Europe/Moscow',
    active BOOLEAN NOT NULL DEFAULT true,
    valid_from DATE NULL,
    valid_to DATE NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT brigade_schedule_day_of_week_check CHECK (day_of_week BETWEEN 1 AND 7),
    CONSTRAINT brigade_schedule_time_check CHECK (starts_at <> ends_at),
    CONSTRAINT brigade_schedule_valid_range_check CHECK (
        valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from
    )
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE brigade_schedule CASCADE;

-- +goose StatementEnd
