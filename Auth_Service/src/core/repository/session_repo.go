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

type SessionRepoStruct struct {
	db *sql.DB
}

func NewSessionRepoStruct(db *sql.DB) *SessionRepoStruct {
	return &SessionRepoStruct{db: db}
}

func (s *SessionRepoStruct) Create(ctx context.Context, session *models.Session) (uuid.UUID, error) {
	var id uuid.UUID

	const query = `INSERT INTO sessions (
    user_id, client_id, ip, user_agent, revoked_at, expires_at, last_seen_at) 
	VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err := s.db.QueryRowContext(
		ctx,
		query,
		session.UserID,
		session.ClientID,
		session.IP,
		session.UserAgent,
		session.RevokedAt,
		session.ExpiresAt,
		session.LastSeenAt,
	).Scan(&id)

	if err != nil {
		return uuid.Nil, fmt.Errorf("session_repo: Create(): %w", err)
	}

	logrus.Printf("Created session with id: %v", id)

	return id, nil

}

func (s *SessionRepoStruct) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	var session models.Session

	const query = `SELECT id, user_id, client_id, ip, user_agent, is_revoked,  revoked_at, expires_at, last_seen_at, created_at FROM sessions WHERE id = $1`

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
		&session.ClientID,
		&session.IP,
		&session.UserAgent,
		&session.IsRevoked,
		&session.RevokedAt,
		&session.ExpiresAt,
		&session.LastSeenAt,
		&session.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session_repo: GetByID(): session not found: %w", err)
		}
		return nil, fmt.Errorf("session_repo: GetByID(): %w", err)
	}

	return &session, nil
}

func (s *SessionRepoStruct) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	var sessions []*models.Session

	const quesry = `SELECT id, user_id, client_id, ip, user_agent, is_revoked, revoked_at, expires_at, last_seen_at, created_at FROM sessions WHERE user_id = $1`

	rows, err := s.db.QueryContext(ctx, quesry, userID)
	if err != nil {

		return nil, fmt.Errorf("session_repo: GetByUserID(): %w", err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			logrus.Errorf("session_repo: GetByUserID(): rows.Close(): %w", err)
		}
	}(rows)

	for rows.Next() {
		var session models.Session
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.ClientID,
			&session.IP,
			&session.UserAgent,
			&session.IsRevoked,
			&session.RevokedAt,
			&session.ExpiresAt,
			&session.LastSeenAt,
			&session.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("session_repo: GetByUserID(): cant scan rows: %w", err)
		}
		sessions = append(sessions, &session)

	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session_repo: GetByUserID(): %w", err)
	}
	return sessions, nil
}

func (s *SessionRepoStruct) RevokeByID(ctx context.Context, sessionID uuid.UUID) error {
	const query = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() AND is_revoked = FALSE WHERE id = $1`

	_, err := s.db.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("session_repo: RevokeByID(): %w", err)
	}

	logrus.Printf("Revoked session with id: %v", sessionID)

	return nil

}

func (s *SessionRepoStruct) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	const query = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() AND is_revoked = FALSE WHERE user_id = $1`

	result, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("session_repo: RevokeAllByUserID(): %w", err)
	}

	rowAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session_repo: RevokeAllByUserID(): %w", err)
	}
	logrus.Printf("Revoked all (%v) sessions with id: %v", rowAffected, userID)
	return rowAffected, nil
}

func (s *SessionRepoStruct) UpdateLastSeen(ctx context.Context, sessionID uuid.UUID) error {
	const query = `UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND is_revoked = FALSE`

	_, err := s.db.ExecContext(ctx, query, sessionID)

	if err != nil {
		return fmt.Errorf("session_repo: UpdateLastSeen(): %w", err)
	}

	logrus.Printf("Updated last seen session with id: %v", sessionID)
	return nil
}
