package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
)

type TXRepoStruct struct {
	db *sql.DB
}

func NewTXRepoStruct(db *sql.DB) *TXRepoStruct {
	return &TXRepoStruct{db}
}

func (t *TXRepoStruct) ChangePassword(ctx context.Context, userID uuid.UUID, password string, sessionID uuid.UUID, revokeOtherSessions bool) (int32, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("tx_repo: ChangePassword() :cant begin transaction: %w", err)
	}

	const updatePassword = `UPDATE users SET password_hash=$1 WHERE id = $2;`

	_, err = tx.ExecContext(ctx, updatePassword, password, userID)

	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return 0, errTX
		}
		return 0, fmt.Errorf("tx_repo: ChangePassword() :cant update user: %w", err)
	}

	if !revokeOtherSessions {
		const revokeSessionQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE id = $1 AND is_revoked = FALSE `
		result, err := tx.ExecContext(ctx, revokeSessionQuery, sessionID)
		if err != nil {
			errTX := tx.Rollback()
			if errTX != nil {
				return 0, fmt.Errorf("tx_repo: changePassword(): revoke session failed: %v; rollback failed: %w", err, errTX)
			}
			return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke session failed: %w", err)
		}

		rowAffected, err := result.RowsAffected()
		if err != nil {
			errTX := tx.Rollback()
			if errTX != nil {
				return 0, fmt.Errorf("tx_repo: changePassword(): RowsAffected failed: %v; rollback failed: %w", err, errTX)
			}
			return 0, fmt.Errorf("tx_repo: ChangePassword(): RowsAffected failed: %w", err)

		}

		const revokeTokenQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE session_id = $1 AND is_revoked = FALSE`
		_, err = tx.ExecContext(ctx, revokeTokenQuery, sessionID)
		if err != nil {
			errTX := tx.Rollback()
			if errTX != nil {
				return 0, fmt.Errorf("tx_repo: changePassword(): revoke token failed: %v; rollback failed: %w", err, errTX)
			}
			return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke token failed: %w", err)
		}

		err = tx.Commit()
		if err != nil {
			return 0, err
		}
		return int32(rowAffected), nil
	}

	const revokeSessionsQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	result, err := tx.ExecContext(ctx, revokeSessionsQuery, userID)
	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: changePassword(): revoke session failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke session failed: %w", err)
	}

	rowAffected, err := result.RowsAffected()
	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: changePassword(): RowsAffected failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ChangePassword(): RowsAffected failed: %w", err)

	}

	const revokeTokensQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	_, err = tx.ExecContext(ctx, revokeTokensQuery, userID)
	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: changePassword(): revoke tokens failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ChangePassword() :revoke tokens failed: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return 0, fmt.Errorf("tx_repo: ChangePassword() :cant commit : %w", err)
	}
	return int32(rowAffected), nil
}

func (t *TXRepoStruct) Logout(ctx context.Context, sessionID uuid.UUID) error {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("tx_repo: logout() :cant begin transaction: %w", err)
	}

	const revokeSessionQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE id = $1 AND is_revoked = FALSE`

	_, err = tx.ExecContext(ctx, revokeSessionQuery, sessionID)
	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return fmt.Errorf("tx_repo: logout(): revoke session failed: %v; rollback failed: %w", err, errTX)
		}

		return fmt.Errorf("tx_repo: logout() :revoke session failed: %w", err)
	}

	const revokeTokenQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE session_id = $1 AND is_revoked = FALSE`
	_, err = tx.ExecContext(ctx, revokeTokenQuery, sessionID)
	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return fmt.Errorf("tx_repo: logout(): revoke token failed: %v; rollback failed: %w", err, errTX)
		}
		return fmt.Errorf("tx_repo: logout() :cant revoke token: %w", err)
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("tx_repo: logout() :cant commit transaction: %w", err)
	}
	return nil
}

func (t *TXRepoStruct) LogoutAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("tx_repo: LogoutAll() :cant begin transaction: %w", err)
	}
	const revokeSessionsQuery = `UPDATE sessions SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`

	result, err := tx.ExecContext(ctx, revokeSessionsQuery, userID)
	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke sessions failed: %v; rollback failed: %w", err, errTX)
		}

		return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke sessions failed: %w", err)
	}

	rowAffected, err := result.RowsAffected()
	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: LogoutAll(): RowsAffected failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: LogoutAll(): RowsAffected failed: %w", err)
	}

	const revokeTokensQuery = `UPDATE refresh_tokens SET is_revoked = TRUE, revoked_at = now() WHERE user_id = $1 AND is_revoked = FALSE`
	_, err = tx.ExecContext(ctx, revokeTokensQuery, userID)

	if err != nil {
		errTX := tx.Rollback()
		if errTX != nil {
			return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke tokens failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: LogoutAll(): revoke tokens failed: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return 0, err
	}

	return rowAffected, nil

}

func (t *TXRepoStruct) ResetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) (int32, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant begin transaction: %w", err)
	}

	const updatePasswordQuery = `
		UPDATE users
		SET password_hash = $1, updated_at = now()
		WHERE id = $2
	`

	result, err := tx.ExecContext(ctx, updatePasswordQuery, passwordHash, userID)
	if err != nil {
		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): update password failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant update password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): rowsAffected failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant get affected rows after password update: %w", err)
	}

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

	result, err = tx.ExecContext(ctx, revokeSessionsQuery, userID)
	if err != nil {
		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): revoke sessions failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant revoke sessions: %w", err)
	}

	sessionRowsAffected, err := result.RowsAffected()
	if err != nil {
		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): session rowsAffected failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant get affected rows after revoking sessions: %w", err)
	}

	const revokeTokensQuery = `
		UPDATE refresh_tokens
		SET is_revoked = TRUE, revoked_at = now()
		WHERE user_id = $1 AND is_revoked = FALSE
	`

	_, err = tx.ExecContext(ctx, revokeTokensQuery, userID)
	if err != nil {
		if errTX := tx.Rollback(); errTX != nil {
			return 0, fmt.Errorf("tx_repo: ResetPassword(): revoke tokens failed: %v; rollback failed: %w", err, errTX)
		}
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant revoke tokens: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("tx_repo: ResetPassword(): cant commit transaction: %w", err)
	}

	return int32(sessionRowsAffected), nil
}
