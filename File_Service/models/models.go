package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrValidation       = errors.New("validation failed")
	ErrPermissionDenied = errors.New("permission denied")
)

type Status string

const (
	StatusPendingUpload Status = "PENDING_UPLOAD"
	StatusUploaded      Status = "UPLOADED"
	StatusLinked        Status = "LINKED"
	StatusDeleted       Status = "DELETED"
	StatusQuarantined   Status = "QUARANTINED"
)

type File struct {
	ID           uuid.UUID  `json:"id"`
	OwnerUserID  uuid.UUID  `json:"owner_user_id"`
	ResourceType *string    `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty"`
	Name         string     `json:"name"`
	ContentType  string     `json:"content_type"`
	Size         int64      `json:"size"`
	Checksum     string     `json:"checksum"`
	ObjectKey    string     `json:"-"`
	Status       Status     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type CreateInput struct {
	OwnerUserID uuid.UUID `json:"owner_user_id"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	Checksum    string    `json:"checksum"`
}

type LinkInput struct {
	ResourceType string    `json:"resource_type"`
	ResourceID   uuid.UUID `json:"resource_id"`
}

type PresignedFile struct {
	File      *File     `json:"file"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}
