package repository

import (
	"auth/models"
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sirupsen/logrus"
)

type UserRepoStruct struct {
	writeDB DBTX
	readDB  DBTX
}

type userRegisteredEventPayload struct {
	UserID        uuid.UUID `json:"user_id"`
	Email         string    `json:"email"`
	Username      string    `json:"username"`
	IsActive      bool      `json:"is_active"`
	EmailVerified bool      `json:"email_verified"`
}

func NewUserRepoStruct(writeDB DBTX, readDB ...DBTX) *UserRepoStruct {
	reader := writeDB
	if len(readDB) > 0 && readDB[0] != nil {
		reader = readDB[0]
	}
	return &UserRepoStruct{writeDB: writeDB, readDB: reader}
}

func (u *UserRepoStruct) CreateUser(ctx context.Context, user *models.User) (uuid.UUID, error) {
	var id uuid.UUID
	err := withTransaction(ctx, u.writeDB, "CreateUser()", func(txExec DBTX) error {
		txRepo := NewUserRepoStruct(txExec)
		var err error
		id, err = txRepo.createUser(ctx, user)
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}

	return id, nil
}

func (u *UserRepoStruct) createUser(ctx context.Context, user *models.User) (uuid.UUID, error) {
	var id uuid.UUID
	const query = `INSERT INTO users (
			email, username, password_hash, is_active, email_verified
		) VALUES ($1, $2, $3, $4, $5)
		RETURNING id`

	err := u.writeDB.QueryRow(
		ctx,
		query,
		user.Email,
		user.Username,
		user.PasswordHash,
		user.IsActive,
		user.EmailVerified,
	).Scan(&id)

	if err != nil {
		return uuid.Nil, fmt.Errorf("user_repo: Create() :cant create user: %w", err)
	}

	tag, err := u.writeDB.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id
		FROM roles
		WHERE name = 'user'
		ON CONFLICT (user_id, role_id) DO NOTHING`, id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("user_repo: Create(): assign default role: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return uuid.Nil, fmt.Errorf("user_repo: Create(): default role user is not seeded")
	}

	logrus.Printf("Created user with id: %v", id)

	if err = insertOutboxEvent(ctx, u.writeDB, "user", id, "auth.user.registered", userRegisteredEventPayload{
		UserID:        id,
		Email:         user.Email,
		Username:      user.Username,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
	}); err != nil {
		return uuid.Nil, fmt.Errorf("user_repo: Create(): insert outbox event: %w", err)
	}

	return id, nil
}
func (u *UserRepoStruct) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User

	const query = `SELECT id, email, username, password_hash, is_active, email_verified, created_at, updated_at  FROM users WHERE id = $1;`
	err := u.readDB.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.IsActive,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user_repo: GetByID(): user not found: %w", err)
		}
		return nil, fmt.Errorf("user_repo: GetUserByID(): %w", err)
	}

	return &user, nil
}
func (u *UserRepoStruct) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User

	const query = `SELECT id, email, username, password_hash, is_active, email_verified, created_at, updated_at  FROM users WHERE email = $1;`
	err := u.readDB.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.IsActive,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user_repo: GetByEmail(): user not exist :%w", err)
		}
		return nil, fmt.Errorf("user_repo: GetByEmail(): %w", err)
	}

	return &user, nil
}
func (u *UserRepoStruct) UpdateUser(ctx context.Context, user *models.User) error {
	const query = `UPDATE users SET email=$1, username=$2, password_hash=$3, is_active=$4, email_verified=$5 WHERE id = $6;`

	_, err := u.writeDB.Exec(
		ctx, query, user.Email,
		user.Username,
		user.PasswordHash,
		user.IsActive,
		user.EmailVerified,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("user_repo: Update() :cant update user: %w", err)
	}

	logrus.Printf("user %s updated", user.ID)
	return nil
}
