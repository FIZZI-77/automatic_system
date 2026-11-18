package models

import "time"

// File описывает метаданные хранимого файла.
type File struct {
	ID           string     `json:"id"`
	OwnerUserID  string     `json:"owner_user_id"`
	ResourceType *string    `json:"resource_type,omitempty"`
	ResourceID   *string    `json:"resource_id,omitempty"`
	Name         string     `json:"name"`
	ContentType  string     `json:"content_type"`
	Size         int64      `json:"size"`
	Checksum     string     `json:"checksum"`
	Status       string     `json:"status"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// CreateFileUploadRequest содержит параметры API-запроса.
type CreateFileUploadRequest struct {
	Name        string `json:"name" binding:"required,max=255"`
	ContentType string `json:"content_type" binding:"required,max=127"`
	Size        int64  `json:"size" binding:"required,gt=0"`
	Checksum    string `json:"checksum,omitempty"`
}

// LinkFileRequest содержит параметры API-запроса.
type LinkFileRequest struct {
	FileID       string `json:"file_id" binding:"required,uuid"`
	ResourceType string `json:"resource_type" binding:"required,max=64"`
	ResourceID   string `json:"resource_id" binding:"required,uuid"`
}

// FileIDRequest содержит параметры API-запроса.
type FileIDRequest struct {
	FileID string `json:"file_id" binding:"required,uuid"`
}

// ListResourceFilesRequest содержит параметры API-запроса.
type ListResourceFilesRequest struct {
	ResourceType string `json:"resource_type" binding:"required,max=64"`
	ResourceID   string `json:"resource_id" binding:"required,uuid"`
}
