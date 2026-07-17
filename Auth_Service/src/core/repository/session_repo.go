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

type SessionRepoStruct struct {
	writeDB DBTX
	readDB  DBTX
}

func NewSessionRepoStruct(writeDB DBTX, readDB ...DBTX) *SessionRepoStruct {
	reader := writeDB
	if len(readDB) > 0 && readDB[0] != nil {
		reader = readDB[0]
	}
	return &SessionRepoStruct{writeDB: writeDB, readDB: reader}
}

func (s *SessionRepoStruct) CreateSession(ctx context.Context, session *models.Session) (uuid.UUID, error) {
	var id uuid.UUID

	const query = `INSERT INTO sessions (
    user_id, client_id, ip, user_agent, revoked_at, expires_at, last_seen_at) 
	VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err := s.writeDB.QueryRow(
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

func (s *SessionRepoStruct) GetSessionByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	var session models.Session

	const query = `SELECT id, user_id, client_id, ip, user_agent, is_revoked,  revoked_at, expires_at, last_seen_at, created_at FROM sessions WHERE id = $1`

	err := s.readDB.QueryRow(ctx, query, id).Scan(
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("session_repo: GetByID(): session not found: %w", err)
		}
		return nil, fmt.Errorf("session_repo: GetByID(): %w", err)
	}

	return &session, nil
}

func (s *SessionRepoStruct) GetSessionByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	var sessions []*models.Session

	const quesry = `SELECT id, user_id, client_id, ip, user_agent, is_revoked, revoked_at, expires_at, last_seen_at, created_at FROM sessions WHERE user_id = $1`

	rows, err := s.readDB.Query(ctx, quesry, userID)
	if err != nil {

		return nil, fmt.Errorf("session_repo: GetByUserID(): %w", err)
	}
	defer rows.Close()

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

func (s *SessionRepoStruct) RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error {
	const query = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE id = $1 AND is_revoked = FALSE`

	_, err := s.writeDB.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("session_repo: RevokeByID(): %w", err)
	}

	logrus.Printf("Revoked session with id: %v", sessionID)

	return nil

}

func (s *SessionRepoStruct) RevokeAllSessionByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	const query = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`

	result, err := s.writeDB.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("session_repo: RevokeAllByUserID(): %w", err)
	}

	rowAffected := result.RowsAffected()
	logrus.Printf("Revoked all (%v) sessions with id: %v", rowAffected, userID)
	return rowAffected, nil
}

func (s *SessionRepoStruct) UpdateLastSeenSession(ctx context.Context, sessionID uuid.UUID) error {
	const query = `UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND is_revoked = FALSE`

	_, err := s.writeDB.Exec(ctx, query, sessionID)

	if err != nil {
		return fmt.Errorf("session_repo: UpdateLastSeen(): %w", err)
	}

	logrus.Printf("Updated last seen session with id: %v", sessionID)
	return nil
}
