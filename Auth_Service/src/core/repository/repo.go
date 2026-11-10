package repository

import (
	"auth/models"
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository interface {
	// CreateUser сохраняет учётную запись, назначает роль user и создаёт событие регистрации.
	CreateUser(ctx context.Context, user *models.User) (uuid.UUID, error)
	// DeleteUserRegistration компенсирует регистрацию удалением пользователя и неотправленного события.
	DeleteUserRegistration(ctx context.Context, userID uuid.UUID) error
	// GetUserByID возвращает учётную запись с хешем пароля по UUID.
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	// GetUserByEmail ищет учётную запись по точному адресу почты, включая хеш пароля.
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	// UpdateUser заменяет сохраняемые учётные поля пользователя по его ID.
	UpdateUser(ctx context.Context, user *models.User) error
}

type SessionRepository interface {
	// CreateSession сохраняет сведения и сроки сессии и возвращает новый UUID.
	CreateSession(ctx context.Context, session *models.Session) (uuid.UUID, error)
	// GetSessionByID возвращает сессию по UUID, включая признаки отзыва и сроки.
	GetSessionByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	// GetSessionByUserID возвращает все сессии пользователя независимо от их состояния.
	GetSessionByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	// RevokeSessionByID отзывает указанную сессию, если она ещё не отозвана.
	RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error
	// RevokeAllSessionByUserID отзывает сессии пользователя и возвращает количество изменений.
	RevokeAllSessionByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	// UpdateLastSeenSession отмечает текущим временем БД активность неотозванной сессии.
	UpdateLastSeenSession(ctx context.Context, sessionID uuid.UUID) error
}

type RefreshTokenRepository interface {
	// CreateToken сохраняет хеш refresh-токена вместе с привязкой к сессии и сроком действия.
	CreateToken(ctx context.Context, token *models.RefreshToken) error
	// GetByTokenHash ищет неотозванный refresh-токен по хешу без проверки срока.
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	// RevokeTokenByID помечает указанный refresh-токен отозванным.
	RevokeTokenByID(ctx context.Context, tokenID uuid.UUID) error
	// RevokeTokenBySessionID отзывает refresh-токены указанной сессии.
	RevokeTokenBySessionID(ctx context.Context, sessionID uuid.UUID) error
	// RevokeAllTokenByUserID отзывает refresh-токены пользователя во всех сессиях.
	RevokeAllTokenByUserID(ctx context.Context, userID uuid.UUID) error
	// MarkUsedAndReplaceToken атомарно заменяет неотозванный токен новым и сохраняет связь замены.
	MarkUsedAndReplaceToken(ctx context.Context, oldTokenID uuid.UUID, newToken *models.RefreshToken) error
}

type RoleRepository interface {
	// GetRolesByUserID возвращает имена ролей, назначенных пользователю.
	GetRolesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error)
	// AssignRoleToUser добавляет связь с ролью, допуская повтор существующего назначения.
	AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error
}

type TXRepository interface {
	// ChangePassword сохраняет хеш password и отзывает текущую либо все сессии пользователя.
	// Возвращает количество отозванных сессий; изменения и событие outbox транзакционны.
	ChangePassword(ctx context.Context, userID uuid.UUID, password string, sessionID uuid.UUID, revokeOtherSessions bool) (int32, error)
	// Logout транзакционно отзывает сессию и её токены и сохраняет событие выхода.
	Logout(ctx context.Context, sessionID uuid.UUID) error
	// LogoutAll транзакционно отзывает сессии и токены пользователя и возвращает число сессий.
	LogoutAll(ctx context.Context, userID uuid.UUID) (int64, error)
	// ResetPassword сохраняет хеш пароля и отзывает сессии без проверки одноразового токена.
	ResetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) (int32, error)
	// ResetPasswordWithToken использует токен сброса, меняет хеш и отзывает сессии в одной транзакции.
	ResetPasswordWithToken(ctx context.Context, userID uuid.UUID, passwordHash string, tokenID uuid.UUID) (int32, error)
	// VerifyEmail атомарно использует токен подтверждения и устанавливает подтверждение почты.
	VerifyEmail(ctx context.Context, userID uuid.UUID, tokenID uuid.UUID) error
}

type OneTimeTokenRepo interface {
	// CreateOneTimeToken сохраняет одноразовый токен, дополняя его ID и временем создания.
	CreateOneTimeToken(ctx context.Context, token *models.OneTimeToken) error
	// GetOneTimeTokenByHashAndType ищет токен по хешу и назначению без проверки срока и использования.
	GetOneTimeTokenByHashAndType(ctx context.Context, tokenHash string, tokenType models.TokenType) (*models.OneTimeToken, error)
	// MarkOneTimeTokenUsed отмечает токен использованным; отсутствие или повтор использования — ошибка.
	MarkOneTimeTokenUsed(ctx context.Context, tokenID uuid.UUID) error
	// RevokeUnusedTokensByUserIDAndType отзывает неистёкшие неиспользованные токены данного назначения.
	RevokeUnusedTokensByUserIDAndType(ctx context.Context, userID uuid.UUID, tokenType models.TokenType) error
}

type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	UserRepository
	SessionRepository
	RefreshTokenRepository
	RoleRepository
	TXRepository
	OneTimeTokenRepo
}

type Repo = Repository

// NewRepository собирает репозитории пользователей, ролей, сессий и токенов из пулов БД.
// Если Read не задан, использует Write для чтения; соединения самостоятельно не открывает.
func NewRepository(pools DBPools) *Repository {

	if pools.Read == nil {
		pools.Read = pools.Write
	}

	return &Repository{
		writePool:              pools.Write,
		readPool:               pools.Read,
		UserRepository:         NewUserRepoStruct(pools.Write, pools.Read),
		SessionRepository:      NewSessionRepoStruct(pools.Write, pools.Read),
		RefreshTokenRepository: NewRefreshTokenRepoStruct(pools.Write, pools.Read),
		RoleRepository:         NewRoleRepoStruct(pools.Write, pools.Read),
		TXRepository:           NewTXRepoStruct(pools.Write),
		OneTimeTokenRepo:       NewOneTimeTokenRepoStruct(pools.Write, pools.Read),
	}
}

// NewRepo создаёт репозиторий с одним пулом чтения и записи для совместимости прежних вызовов.
func NewRepo(db *pgxpool.Pool) *Repo {
	return NewRepository(DBPools{
		Write: db,
		Read:  db,
	})
}

// newRepoWithExecutor связывает все вложенные репозитории с одним исполнителем SQL.
// Используется для общей транзакции; корневые пулы в созданном объекте не задаёт.
func newRepoWithExecutor(exec DBTX) *Repo {
	return &Repo{
		UserRepository:         NewUserRepoStruct(exec),
		SessionRepository:      NewSessionRepoStruct(exec),
		RefreshTokenRepository: NewRefreshTokenRepoStruct(exec),
		RoleRepository:         NewRoleRepoStruct(exec),
		TXRepository:           NewTXRepoStruct(exec),
		OneTimeTokenRepo:       NewOneTimeTokenRepoStruct(exec),
	}
}

// WithTx вызывает fn с репозиториями, работающими в одной новой транзакции.
// Фиксирует изменения после успеха fn, иначе выполняет откат; требует корневой writePool.
func (r *Repo) WithTx(ctx context.Context, fn func(txRepo *Repo) error) error {

	if r.writePool == nil {
		return fmt.Errorf("repository: WithTx(): root db is unavailable")
	}

	tx, err := r.writePool.Begin(ctx)

	if err != nil {
		return fmt.Errorf("repository: WithTx(): begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	if err := fn(newRepoWithExecutor(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("repository: WithTx(): commit: %w", err)
	}

	return nil
}
