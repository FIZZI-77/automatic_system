package models

import (
	"time"

	"github.com/google/uuid"
)

// Notification описывает пользовательское уведомление.
type Notification struct {
	ID        uuid.UUID
	EventID   string
	UserID    uuid.UUID
	EventType string
	Title     string
	Body      string
	Data      map[string]string
	Read      bool
	ReadAt    *time.Time
	CreatedAt time.Time
}

// Preferences описывает пользовательские настройки уведомлений.
type Preferences struct {
	UserID       uuid.UUID
	InApp        bool
	Push         bool
	Email        bool
	SMS          bool
	EmailAddress *string
	Phone        *string
	UpdatedAt    time.Time
}

// Device описывает устройство, зарегистрированное для уведомлений.
type Device struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Token     string
	Platform  string
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Template описывает шаблон уведомления для события и канала.
type Template struct {
	ID        uuid.UUID
	EventType string
	Channel   string
	Subject   string
	Body      string
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Delivery описывает попытку доставки уведомления.
type Delivery struct {
	ID             uuid.UUID
	NotificationID uuid.UUID
	Channel        string
	Recipient      string
	Title          string
	Body           string
	Status         string
	ProviderID     *string
	LastError      *string
	Attempts       int32
	NextAttemptAt  time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Event описывает событие event.
type Event struct {
	ID      string
	Type    string
	Topic   string
	Payload map[string]any
}
