package service

import (
	"context"
	"time"
)

// objectStorage описывает операции S3, необходимые файловому сервису.
type objectStorage interface {
	UploadURL(context.Context, string, string, string, int64, time.Duration) (string, error)
	DownloadURL(context.Context, string, string, time.Duration) (string, error)
	Stat(context.Context, string) (int64, string, error)
	Delete(context.Context, string) error
}
