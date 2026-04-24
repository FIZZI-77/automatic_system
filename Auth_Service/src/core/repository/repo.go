package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, user *models.User) (uuid.UUID, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) (uuid.UUID, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	RevokeByID(ctx context.Context, sessionID uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	UpdateLastSeen(ctx context.Context, sessionID uuid.UUID) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *models.RefreshToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	RevokeByID(ctx context.Context, tokenID uuid.UUID) error
	RevokeBySessionID(ctx context.Context, sessionID uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	MarkUsedAndReplace(ctx context.Context, oldTokenID string, newToken *models.RefreshToken) error
}

type RoleRepository interface {
	GetRolesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error)
	AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error
}

type Repo struct {
	UserRepository
	SessionRepository
	RefreshTokenRepository
	RoleRepository
}

func NewRepo(db *sql.DB) *Repo {
	return &Repo{}
}
