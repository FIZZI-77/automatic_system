package repository

import (
	"auth/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UserRepoStruct struct {
	db DBTX
}

type userRegisteredEventPayload struct {
	UserID        uuid.UUID `json:"user_id"`
	Email         string    `json:"email"`
	Username      string    `json:"username"`
	IsActive      bool      `json:"is_active"`
	EmailVerified bool      `json:"email_verified"`
}

func NewUserRepoStruct(db DBTX) *UserRepoStruct {
	return &UserRepoStruct{db: db}
}

func (u *UserRepoStruct) CreateUser(ctx context.Context, user *models.User) (uuid.UUID, error) {
	var id uuid.UUID
	err := withTransaction(ctx, u.db, "CreateUser()", func(txExec DBTX) error {
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

	err := u.db.QueryRowContext(
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

	logrus.Printf("Created user with id: %v", id)

	if err = insertOutboxEvent(ctx, u.db, "user", id, "auth.user.registered", userRegisteredEventPayload{
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
	err := u.db.QueryRowContext(ctx, query, id).Scan(
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user_repo: GetByID(): user not found: %w", err)
		}
		return nil, fmt.Errorf("user_repo: GetUserByID(): %w", err)
	}

	return &user, nil
}
func (u *UserRepoStruct) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User

	const query = `SELECT id, email, username, password_hash, is_active, email_verified, created_at, updated_at  FROM users WHERE email = $1;`
	err := u.db.QueryRowContext(ctx, query, email).Scan(
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user_repo: GetByEmail(): user not exist :%w", err)
		}
		return nil, fmt.Errorf("user_repo: GetByEmail(): %w", err)
	}

	return &user, nil
}
func (u *UserRepoStruct) UpdateUser(ctx context.Context, user *models.User) error {
	const query = `UPDATE users SET email=$1, username=$2, password_hash=$3, is_active=$4, email_verified=$5 WHERE id = $6;`

	_, err := u.db.ExecContext(
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
