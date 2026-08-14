package repository

import (
	"audit/models"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type EntryWriterRepoStruct struct{ db *pgxpool.Pool }

func NewEntryWriterRepoStruct(db *pgxpool.Pool) *EntryWriterRepoStruct {
	return &EntryWriterRepoStruct{db: db}
}
func (r *EntryWriterRepoStruct) Store(ctx context.Context, event models.Event) error {
	data, err := json.Marshal(sanitize(event.Payload))
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	actorID := uuidValue(event.Payload, "actor_id", "actor_user_id", "user_id", "changed_by")
	entityType, entityID := eventEntity(event)
	requestID := metadataValue(event.Headers, event.Payload, "request_id", "x-request-id")
	traceID := metadataValue(event.Headers, event.Payload, "trace_id", "traceparent")
	occurred := event.Timestamp
	if raw := stringValue(event.Payload, "occurred_at", "created_at", "updated_at"); raw != "" {
		if parsed, e := time.Parse(time.RFC3339Nano, raw); e == nil {
			occurred = parsed
		}
	}
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	_, err = r.db.Exec(ctx, `INSERT INTO audit_entries(event_id,topic,action,actor_id,entity_type,entity_id,request_id,trace_id,data,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(topic,event_id) DO NOTHING`, event.ID, event.Topic, event.Type, actorID, entityType, entityID, requestID, traceID, data, occurred)
	return err
}
