-- +goose Up
-- +goose StatementBegin
INSERT INTO sla_rules (
    name,
    priority,
    response_seconds,
    resolution_seconds,
    warning_percent
)
VALUES
    ('Default emergency', 'EMERGENCY', 300, 3600, 80),
    ('Default high', 'HIGH', 1800, 14400, 80),
    ('Default medium', 'MEDIUM', 7200, 86400, 80),
    ('Default low', 'LOW', 14400, 259200, 80);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM sla_rules
WHERE name IN (
    'Default emergency',
    'Default high',
    'Default medium',
    'Default low'
);
-- +goose StatementEnd
