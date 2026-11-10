-- +goose Up
-- +goose StatementBegin
INSERT INTO notification_templates (event_type, channel, subject, body)
VALUES
    ('sla.RESPONSE_WARNING', 'IN_APP', 'Срок реакции истекает', 'По заявке {{ticket_id}} приближается срок реакции'),
    ('sla.RESPONSE_BREACHED', 'IN_APP', 'Нарушен SLA реакции', 'По заявке {{ticket_id}} нарушен срок реакции'),
    ('sla.RESOLUTION_WARNING', 'IN_APP', 'Срок выполнения истекает', 'По заявке {{ticket_id}} приближается срок выполнения'),
    ('sla.RESOLUTION_BREACHED', 'IN_APP', 'Нарушен SLA выполнения', 'По заявке {{ticket_id}} нарушен срок выполнения'),
    ('ticket.assigned', 'IN_APP', 'Назначена заявка', 'Заявка {{ticket_id}} назначена бригаде'),
    ('ticket.completed', 'IN_APP', 'Заявка выполнена', 'Работы по заявке {{ticket_id}} завершены')
ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM notification_templates
WHERE channel = 'IN_APP'
  AND event_type IN (
      'sla.RESPONSE_WARNING',
      'sla.RESPONSE_BREACHED',
      'sla.RESOLUTION_WARNING',
      'sla.RESOLUTION_BREACHED',
      'ticket.assigned',
      'ticket.completed'
  );
-- +goose StatementEnd
