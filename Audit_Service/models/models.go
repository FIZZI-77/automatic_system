package models

import (
	"time"

	"github.com/google/uuid"
)

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

type Event struct {
	ID, Type, Topic string
	Payload         map[string]any
	Headers         map[string]string
	Timestamp       time.Time
}
