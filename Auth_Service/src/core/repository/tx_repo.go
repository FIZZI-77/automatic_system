package repository

import (
	"context"
	"fmt"

	"auth/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TXRepoStruct struct {
	writeDB DBTX
}

type authTx struct {
	pgx.Tx
	ctx context.Context
}

// Commit фиксирует обёрнутую транзакцию с сохранённым в authTx контекстом.
func (t authTx) Commit() error {
	return t.Tx.Commit(t.ctx)
}

// Rollback откатывает обёрнутую транзакцию с сохранённым в authTx контекстом.
func (t authTx) Rollback() error {
	return t.Tx.Rollback(t.ctx)
}

// NewTXRepoStruct создаёт репозиторий составных изменений пользователя, сессий и токенов.
func NewTXRepoStruct(writeDB DBTX) *TXRepoStruct {
	return &TXRepoStruct{writeDB: writeDB}
}

// insertAuthOutboxEvent записывает доменное событие через общий outbox в переданной транзакции.
func insertAuthOutboxEvent(ctx context.Context, tx DBTX, aggregateType string, aggregateID uuid.UUID, eventType string, payload any) error {
	return insertOutboxEvent(ctx, tx, aggregateType, aggregateID, eventType, payload)
}

// ChangePassword сохраняет переданный хеш password и событие смены пароля в транзакции.
// При revokeOtherSessions=false отзывает текущую сессию и её токены, при true — все сессии
// и токены пользователя. Возвращает количество отозванных сессий.
func (t *TXRepoStruct) ChangePassword(ctx context.Context, userID uuid.UUID, password string, sessionID uuid.UUID, revokeOtherSessions bool) (int32, error) {
	pgxTx, err := beginNestedAware(ctx, t.writeDB)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ChangePassword() :cant begin transaction: %w", err)
	}

	tx := authTx{
		Tx:  pgxTx,
		ctx: ctx,
	}

	const updatePassword = `UPDATE users SET password_hash=$1 WHERE id = $2;`

	_, err = tx.Exec(ctx, updatePassword, password, userID)

	if err != nil {
		errTX := tx.Rollback()

		if errTX != nil {
			return 0, errTX
		}

		return 0, fmt.Errorf("tx_repo: ChangePassword() :cant update user: %w", err)
	}

	if !revokeOtherSessions {
		const revokeSessionQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE id = $1 AND is_revoked = FALSE `
		result, err := tx.Exec(ctx, revokeSessionQuery, sessionID)

		if err != nil {
			errTX := tx.Rollback()

			if errTX != nil {
				return 0, fmt.Errorf("tx_repo: changePassword(): revoke session failed: %v; rollback failed: %w", err, errTX)
			}

			return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke session failed: %w", err)
		}

		rowAffected := result.RowsAffected()

		const revokeTokenQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE session_id = $1 AND is_revoked = FALSE`
		_, err = tx.Exec(ctx, revokeTokenQuery, sessionID)

		if err != nil {
			errTX := tx.Rollback()

			if errTX != nil {
				return 0, fmt.Errorf("tx_repo: changePassword(): revoke token failed: %v; rollback failed: %w", err, errTX)
			}

			return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke token failed: %w", err)
		}

		if err = insertAuthOutboxEvent(ctx, tx, "user", userID, "auth.user.password_changed", map[string]any{
			"user_id":                 userID,
			"session_id":              sessionID,
			"revoke_other_sessions":   revokeOtherSessions,
			"invalidated_session_cnt": rowAffected,
		}); err != nil {

			if errTX := tx.Rollback(); errTX != nil {
				return 0, fmt.Errorf("tx_repo: ChangePassword(): insert outbox failed: %v; rollback failed: %w", err, errTX)
			}

			return 0, fmt.Errorf("tx_repo: ChangePassword(): insert outbox event: %w", err)
		}

		err = tx.Commit()

		if err != nil {
			return 0, err
		}

		return int32(rowAffected), nil
	}

	const revokeSessionsQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	result, err := tx.Exec(ctx, revokeSessionsQuery, userID)

	if err != nil {
		errTX := tx.Rollback()

		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: changePassword(): revoke session failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke session failed: %w", err)
	}

	rowAffected := result.RowsAffected()

	const revokeTokensQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	_, err = tx.Exec(ctx, revokeTokensQuery, userID)

	if err != nil {
		errTX := tx.Rollback()

		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: changePassword(): revoke tokens failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke tokens failed: %w", err)
	}

	if err = insertAuthOutboxEvent(ctx, tx, "user", userID, "auth.user.password_changed", map[string]any{
		"user_id":                 userID,
		"session_id":              sessionID,
		"revoke_other_sessions":   revokeOtherSessions,
		"invalidated_session_cnt": rowAffected,
	}); err != nil {

		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ChangePassword(): insert outbox failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: ChangePassword(): insert outbox event: %w", err)
	}

	err = tx.Commit()

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ChangePassword() :cant commit : %w", err)
	}

	return int32(rowAffected), nil
}

// Logout транзакционно отзывает сессию, её refresh-токены и сохраняет событие выхода в outbox.
func (t *TXRepoStruct) Logout(ctx context.Context, sessionID uuid.UUID) error {
	pgxTx, err := beginNestedAware(ctx, t.writeDB)

	if err != nil {
		return fmt.Errorf("tx_repo: logout() :cant begin transaction: %w", err)
	}

	tx := authTx{
		Tx:  pgxTx,
		ctx: ctx,
	}

	const revokeSessionQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE id = $1 AND is_revoked = FALSE`

	_, err = tx.Exec(ctx, revokeSessionQuery, sessionID)

	if err != nil {
		errTX := tx.Rollback()

		if errTX != nil {
			return fmt.Errorf("tx_repo: logout(): revoke session failed: %v; rollback failed: %w", err, errTX)
		}

		return fmt.Errorf("tx_repo: logout() :revoke session failed: %w", err)
	}

	const revokeTokenQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE session_id = $1 AND is_revoked = FALSE`
	_, err = tx.Exec(ctx, revokeTokenQuery, sessionID)

	if err != nil {
		errTX := tx.Rollback()

		if errTX != nil {
			return fmt.Errorf("tx_repo: logout(): revoke token failed: %v; rollback failed: %w", err, errTX)
		}

		return fmt.Errorf("tx_repo: logout() :cant revoke token: %w", err)
	}

	if err = insertAuthOutboxEvent(ctx, tx, "session", sessionID, "auth.session.logged_out", map[string]any{
		"session_id": sessionID,
	}); err != nil {

		if errTX := tx.Rollback(); errTX != nil {
			return fmt.Errorf("tx_repo: logout(): insert outbox failed: %v; rollback failed: %w", err, errTX)
		}

		return fmt.Errorf("tx_repo: logout(): insert outbox event: %w", err)
	}

	err = tx.Commit()

	if err != nil {
		return fmt.Errorf("tx_repo: logout() :cant commit transaction: %w", err)
	}

	return nil
}

// LogoutAll отзывает все сессии и refresh-токены пользователя и сохраняет событие outbox.
// Возвращает число сессий, изменённых в транзакции.
func (t *TXRepoStruct) LogoutAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	pgxTx, err := beginNestedAware(ctx, t.writeDB)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: LogoutAll() :cant begin transaction: %w", err)
	}

	tx := authTx{
		Tx:  pgxTx,
		ctx: ctx,
	}
	const revokeSessionsQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`

	result, err := tx.Exec(ctx, revokeSessionsQuery, userID)

	if err != nil {
		errTX := tx.Rollback()

		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke sessions failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke sessions failed: %w", err)
	}

	rowAffected := result.RowsAffected()

	const revokeTokensQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	_, err = tx.Exec(ctx, revokeTokensQuery, userID)

	if err != nil {
		errTX := tx.Rollback()

		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke tokens failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke tokens failed: %w", err)
	}

	if err = insertAuthOutboxEvent(ctx, tx, "user", userID, "auth.user.logged_out_all", map[string]any{
		"user_id":                 userID,
		"invalidated_session_cnt": rowAffected,
	}); err != nil {

		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: LogoutAll(): insert outbox failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: LogoutAll(): insert outbox event: %w", err)
	}

	err = tx.Commit()

	if err != nil {
		return 0, err
	}

	return rowAffected, nil

}

// ResetPassword транзакционно меняет хеш пароля, отзывает сессии и токены и сохраняет событие.
// Одноразовый токен не проверяет; возвращает число отозванных сессий.
func (t *TXRepoStruct) ResetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) (int32, error) {
	pgxTx, err := beginNestedAware(ctx, t.writeDB)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant begin transaction: %w", err)
	}

	tx := authTx{
		Tx:  pgxTx,
		ctx: ctx,
	}

	const updatePasswordQuery = `
		UPDATE users
		SET password_hash = $1, updated_at = now()
		WHERE id = $2
	`

	result, err := tx.Exec(ctx, updatePasswordQuery, passwordHash, userID)

	if err != nil {

		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): update password failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant update password: %w", err)
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {

		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): user not found; rollback failed: %w", errTX)
		}

		return 0, fmt.Errorf("tx_repo: ResetPassword(): user not found")
	}

	const revokeSessionsQuery = `
		UPDATE sessions
		SET is_revoked = TRUE, revoked_at = now()
		WHERE user_id = $1 AND is_revoked = FALSE
	`

	result, err = tx.Exec(ctx, revokeSessionsQuery, userID)

	if err != nil {

		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): revoke sessions failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant revoke sessions: %w", err)
	}

	sessionRowsAffected := result.RowsAffected()

	const revokeTokensQuery = `
		UPDATE refresh_tokens
		SET is_revoked = TRUE, revoked_at = now()
		WHERE user_id = $1 AND is_revoked = FALSE
	`

	_, err = tx.Exec(ctx, revokeTokensQuery, userID)

	if err != nil {

		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): revoke tokens failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant revoke tokens: %w", err)
	}

	if err = insertAuthOutboxEvent(ctx, tx, "user", userID, "auth.user.password_reset", map[string]any{
		"user_id":                 userID,
		"invalidated_session_cnt": sessionRowsAffected,
	}); err != nil {

		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): insert outbox failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: ResetPassword(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant commit transaction: %w", err)
	}

	return int32(sessionRowsAffected), nil
}

// ResetPasswordWithToken атомарно использует действующий токен сброса, меняет хеш пароля,
// отзывает сессии и токены и сохраняет событие. Возвращает число отозванных сессий;
// использованный, истёкший или отсутствующий токен вызывает ошибку без смены пароля.
func (t *TXRepoStruct) ResetPasswordWithToken(ctx context.Context, userID uuid.UUID, passwordHash string, tokenID uuid.UUID) (int32, error) {
	pgxTx, err := beginNestedAware(ctx, t.writeDB)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): cant begin transaction: %w", err)
	}

	tx := authTx{
		Tx:  pgxTx,
		ctx: ctx,
	}
	defer tx.Rollback()

	const markTokenUsedQuery = `
		UPDATE one_time_tokens
		SET used_at = now()
		WHERE id = $1
		  AND user_id = $2
		  AND type = $3
		  AND used_at IS NULL
		  AND expires_at > now()
	`

	result, err := tx.Exec(ctx, markTokenUsedQuery, tokenID, userID, models.TokenTypePasswordReset)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): mark token used: %w", err)
	}

	tokenRowsAffected := result.RowsAffected()

	if tokenRowsAffected == 0 {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): token not found, expired or already used")
	}

	const updatePasswordQuery = `
		UPDATE users
		SET password_hash = $1, updated_at = now()
		WHERE id = $2
	`

	result, err = tx.Exec(ctx, updatePasswordQuery, passwordHash, userID)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): update password: %w", err)
	}

	userRowsAffected := result.RowsAffected()

	if userRowsAffected == 0 {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): user not found")
	}

	const revokeSessionsQuery = `
		UPDATE sessions
		SET is_revoked = TRUE, revoked_at = now()
		WHERE user_id = $1 AND is_revoked = FALSE
	`

	result, err = tx.Exec(ctx, revokeSessionsQuery, userID)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): revoke sessions: %w", err)
	}

	sessionRowsAffected := result.RowsAffected()

	const revokeTokensQuery = `
		UPDATE refresh_tokens
		SET is_revoked = TRUE, revoked_at = now()
		WHERE user_id = $1 AND is_revoked = FALSE
	`

	_, err = tx.Exec(ctx, revokeTokensQuery, userID)

	if err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): revoke tokens: %w", err)
	}

	if err = insertAuthOutboxEvent(ctx, tx, "user", userID, "auth.user.password_reset", map[string]any{
		"user_id":                 userID,
		"token_id":                tokenID,
		"invalidated_session_cnt": sessionRowsAffected,
	}); err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPasswordWithToken(): commit: %w", err)
	}

	return int32(sessionRowsAffected), nil
}

// VerifyEmail атомарно помечает действующий токен использованным, подтверждает почту
// пользователя и записывает событие outbox. При неподходящем токене или пользователе откатывается.
func (t *TXRepoStruct) VerifyEmail(ctx context.Context, userID uuid.UUID, tokenID uuid.UUID) error {
	pgxTx, err := beginNestedAware(ctx, t.writeDB)

	if err != nil {
		return fmt.Errorf("tx_repo: VerifyEmail(): cant begin transaction: %w", err)
	}

	tx := authTx{
		Tx:  pgxTx,
		ctx: ctx,
	}
	defer tx.Rollback()

	const markTokenUsedQuery = `
		UPDATE one_time_tokens
		SET used_at = now()
		WHERE id = $1
		  AND user_id = $2
		  AND type = $3
		  AND used_at IS NULL
		  AND expires_at > now()
	`

	result, err := tx.Exec(ctx, markTokenUsedQuery, tokenID, userID, models.TokenTypeEmailVerification)

	if err != nil {
		return fmt.Errorf("tx_repo: VerifyEmail(): mark token used: %w", err)
	}

	tokenRowsAffected := result.RowsAffected()

	if tokenRowsAffected == 0 {
		return fmt.Errorf("tx_repo: VerifyEmail(): token not found, expired or already used")
	}

	const verifyUserQuery = `
		UPDATE users
		SET email_verified = TRUE, updated_at = now()
		WHERE id = $1
	`

	result, err = tx.Exec(ctx, verifyUserQuery, userID)

	if err != nil {
		return fmt.Errorf("tx_repo: VerifyEmail(): verify user: %w", err)
	}

	userRowsAffected := result.RowsAffected()

	if userRowsAffected == 0 {
		return fmt.Errorf("tx_repo: VerifyEmail(): user not found")
	}

	if err = insertAuthOutboxEvent(ctx, tx, "user", userID, "auth.user.email_verified", map[string]any{
		"user_id":  userID,
		"token_id": tokenID,
	}); err != nil {
		return fmt.Errorf("tx_repo: VerifyEmail(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("tx_repo: VerifyEmail(): commit: %w", err)
	}

	return nil
}
