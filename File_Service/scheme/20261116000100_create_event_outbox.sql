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
CREATE FUNCTION enqueue_file_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    kind TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        kind := 'file.created';
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        kind := CASE NEW.status
            WHEN 'UPLOADED' THEN 'file.uploaded'
            WHEN 'LINKED' THEN 'file.linked'
            WHEN 'QUARANTINED' THEN 'file.quarantined'
            WHEN 'DELETED' THEN 'file.deleted'
        END;
    ELSIF (NEW.resource_type, NEW.resource_id) IS DISTINCT FROM (OLD.resource_type, OLD.resource_id) THEN
        kind := 'file.linked';
    END IF;
    IF kind IS NOT NULL THEN
        INSERT INTO outbox_events(aggregate_id,event_type,payload)
        VALUES (NEW.id,kind,jsonb_build_object(
            'entity_type','file','entity_id',NEW.id,'file_id',NEW.id,
            'owner_user_id',NEW.owner_user_id,'resource_type',NEW.resource_type,
            'resource_id',NEW.resource_id,'status',NEW.status,
            'content_type',NEW.content_type,'size',NEW.size));
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER files_event_outbox AFTER INSERT OR UPDATE ON files
    FOR EACH ROW EXECUTE FUNCTION enqueue_file_event();

-- +goose Down
DROP TRIGGER files_event_outbox ON files;
DROP FUNCTION enqueue_file_event();
DROP TABLE outbox_events;
