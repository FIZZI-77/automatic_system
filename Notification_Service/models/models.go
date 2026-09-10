package models

import (
	"github.com/google/uuid"
	"time"
)

type Notification struct {
	ID                     uuid.UUID
	EventID                string
	UserID                 uuid.UUID
	EventType, Title, Body string
	Data                   map[string]string
	Read                   bool
	ReadAt                 *time.Time
	CreatedAt              time.Time
}
type Preferences struct {
	UserID                  uuid.UUID
	InApp, Push, Email, SMS bool
	EmailAddress, Phone     *string
	UpdatedAt               time.Time
}
type Device struct {
	ID, UserID           uuid.UUID
	Token, Platform      string
	Active               bool
	CreatedAt, UpdatedAt time.Time
}
type Template struct {
	ID                                uuid.UUID
	EventType, Channel, Subject, Body string
	Active                            bool
	CreatedAt, UpdatedAt              time.Time
}
type Delivery struct {
	ID, NotificationID                  uuid.UUID
	Channel, Recipient, Status          string
	ProviderID, LastError               *string
	Attempts                            int32
	NextAttemptAt, CreatedAt, UpdatedAt time.Time
}
type Event struct {
	ID, Type, Topic string
	Payload         map[string]any
}
