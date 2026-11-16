-- +goose Up
CREATE TABLE outbox_events (
    sequence BIGSERIAL PRIMARY KEY,
    id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    sent_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT
);
CREATE INDEX outbox_events_pending_idx ON outbox_events(sequence) WHERE sent_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION enqueue_notification_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    kind TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        kind := 'notification.created';
    ELSIF NEW.read AND NOT OLD.read THEN
        kind := 'notification.read';
    END IF;
    IF kind IS NOT NULL THEN
        INSERT INTO outbox_events(aggregate_id,event_type,payload)
        VALUES (NEW.id,kind,jsonb_build_object(
            'entity_type','notification','entity_id',NEW.id,'notification_id',NEW.id,
            'user_id',NEW.user_id,'source_event_id',NEW.event_id,
            'source_event_type',NEW.event_type,'read',NEW.read));
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER notifications_event_outbox AFTER INSERT OR UPDATE ON notifications
    FOR EACH ROW EXECUTE FUNCTION enqueue_notification_event();

-- +goose StatementBegin
CREATE FUNCTION enqueue_delivery_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('SENT','FAILED','DEAD') THEN
        INSERT INTO outbox_events(aggregate_id,event_type,payload)
        SELECT NEW.notification_id,'notification.delivery.' || lower(NEW.status),jsonb_build_object(
            'entity_type','notification','entity_id',NEW.notification_id,
            'notification_id',NEW.notification_id,'delivery_id',NEW.id,
            'user_id',n.user_id,'source_event_id',n.event_id,
            'source_event_type',n.event_type,'channel',NEW.channel,
            'status',NEW.status,'attempts',NEW.attempts)
        FROM notifications n WHERE n.id=NEW.notification_id;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER deliveries_event_outbox AFTER UPDATE ON deliveries
    FOR EACH ROW EXECUTE FUNCTION enqueue_delivery_event();

-- +goose Down
DROP TRIGGER deliveries_event_outbox ON deliveries;
DROP FUNCTION enqueue_delivery_event();
DROP TRIGGER notifications_event_outbox ON notifications;
DROP FUNCTION enqueue_notification_event();
DROP TABLE outbox_events;
