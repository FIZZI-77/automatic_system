package models

import "time"

type GetAuditEntryRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

type ListAuditEntriesRequest struct {
	ActorID    *string    `json:"actor_id,omitempty" binding:"omitempty,uuid"`
	Action     *string    `json:"action,omitempty"`
	EntityType *string    `json:"entity_type,omitempty"`
	EntityID   *string    `json:"entity_id,omitempty"`
	RequestID  *string    `json:"request_id,omitempty"`
	TraceID    *string    `json:"trace_id,omitempty"`
	Topic      *string    `json:"topic,omitempty"`
	From       *time.Time `json:"from,omitempty"`
	To         *time.Time `json:"to,omitempty"`
	Limit      int32      `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
	Offset     int32      `json:"offset,omitempty" binding:"omitempty,min=0"`
}
