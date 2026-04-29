package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"github.com/google/uuid"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) (uuid.UUID, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
}

type SessionRepository interface {
	CreateSession(ctx context.Context, session *models.Session) (uuid.UUID, error)
	GetSessionByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	GetSessionByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error
	RevokeAllSessionByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	UpdateLastSeenSession(ctx context.Context, sessionID uuid.UUID) error
}

type RefreshTokenRepository interface {
	CreateToken(ctx context.Context, token *models.RefreshToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	RevokeTokenByID(ctx context.Context, tokenID uuid.UUID) error
	RevokeTokenBySessionID(ctx context.Context, sessionID uuid.UUID) error
	RevokeAllTokenByUserID(ctx context.Context, userID uuid.UUID) error
	MarkUsedAndReplaceToken(ctx context.Context, oldTokenID uuid.UUID, newToken *models.RefreshToken) error
}

type RoleRepository interface {
	GetRolesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error)
	AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error
}

type TXRepository interface {
	ChangePassword(ctx context.Context, userID uuid.UUID, password string, sessionID uuid.UUID, revokeOtherSessions bool) (int32, error)
	Logout(ctx context.Context, sessionID uuid.UUID) error
	LogoutAll(ctx context.Context, userID uuid.UUID) (int64, error)
	ResetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) (int32, error)
}

type OneTimeTokenRepo interface {
	CreateOneTimeToken(ctx context.Context, token *models.OneTimeToken) error
	GetOneTimeTokenByHashAndType(ctx context.Context, tokenHash string, tokenType models.TokenType) (*models.OneTimeToken, error)
	MarkOneTimeTokenUsed(ctx context.Context, tokenID uuid.UUID) error
	RevokeUnusedTokensByUserIDAndType(ctx context.Context, userID uuid.UUID, tokenType models.TokenType) error
}

type Repo struct {
	UserRepository
	SessionRepository
	RefreshTokenRepository
	RoleRepository
	TXRepository
	OneTimeTokenRepo
}

func NewRepo(db *sql.DB) *Repo {
	return &Repo{
		UserRepository:         NewUserRepoStruct(db),
		SessionRepository:      NewSessionRepoStruct(db),
		RefreshTokenRepository: NewRefreshTokenRepoStruct(db),
		RoleRepository:         NewRoleRepoStruct(db),
		TXRepository:           NewTXRepoStruct(db),
		OneTimeTokenRepo:       NewOneTimeTokenRepoStruct(db),
	}
}
