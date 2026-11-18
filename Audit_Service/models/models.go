package models

import (
	"time"

	"github.com/google/uuid"
)

// Entry описывает доменную модель.
type Entry struct {
	ID         uuid.UUID
	EventID    string
	Topic      string
	Action     string
	ActorID    *uuid.UUID
	EntityType *string
	EntityID   *string
	RequestID  *string
	TraceID    *string
	Data       map[string]any
	OccurredAt time.Time
	RecordedAt time.Time
}

// Filter задаёт условия фильтрации.
type Filter struct {
	ActorID    *uuid.UUID
	Action     *string
	EntityType *string
	EntityID   *string
	RequestID  *string
	TraceID    *string
	Topic      *string
	From       *time.Time
	To         *time.Time
	Limit      int32
	Offset     int32
}

// Event описывает событие event.
type Event struct {
	ID        string
	Type      string
	Topic     string
	Payload   map[string]any
	Headers   map[string]string
	Timestamp time.Time
}
