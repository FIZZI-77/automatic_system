package service

import (
	"auth/models"
	"auth/pkg"
	"auth/src/core/repository"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"time"
)

const ttl = time.Minute * 15
const refreshTTL = time.Hour * 24 * 30
const verifyEmailTTL = time.Hour * 24
const resetPasswordTTL = time.Minute * 30

type AuthServiceStruct struct {
	repo        *repository.Repo
	privateKey  *rsa.PrivateKey
	keyID       string
	mailService MailService
	profiles    ProfileProvisioner
	logger      *zap.Logger
}

func NewAuthServiceStruct(repo *repository.Repo, privateKey *rsa.PrivateKey, keyID string, mailService MailService, profiles ProfileProvisioner, logger *zap.Logger) *AuthServiceStruct {
	return &AuthServiceStruct{repo: repo, privateKey: privateKey, keyID: keyID, mailService: mailService, profiles: profiles, logger: logger}

}

func (a *AuthServiceStruct) Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("starting user registration",
		zap.String("email", in.Email),
		zap.String("username", in.Username),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("registration validation failed",
			zap.String("email", in.Email),
			zap.Error(err),
		)
		return nil, err
	}

	idempotentResult, err := a.withExternalSideEffectIdempotency(ctx, "Register", in.Email, in, func(ctx context.Context) (any, uuid.UUID, error) {
		existingUser, err := a.repo.GetUserByEmail(ctx, in.Email)

		if err == nil && existingUser != nil {
			logger.Warn("registration failed - user already exists",
				zap.String("email", in.Email),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: Register(): %w", models.ErrUserAlreadyExists)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("failed to check existing user",
				zap.String("email", in.Email),
				zap.Error(err),
			)
			return nil, uuid.Nil, err
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("failed to generate password hash", zap.Error(err))
			return nil, uuid.Nil, fmt.Errorf("jwt: Register(): cant hash password: %w", err)
		}

		user := &models.User{
			Username:      in.Username,
			Email:         in.Email,
			PasswordHash:  string(passwordHash),
			IsActive:      true,
			EmailVerified: false,
		}

		id, err := a.repo.CreateUser(ctx, user)

		if err != nil {
			logger.Error("failed to create user in database",
				zap.String("email", in.Email),
				zap.Error(err),
			)
			return nil, uuid.Nil, err
		}

		if a.profiles == nil {
			err = errors.New("profile provisioner is not configured")
		} else {
			err = a.profiles.CreateUserProfile(ctx, id, in.Username)
		}
		if err != nil {
			compensationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if compensationErr := a.repo.DeleteUserRegistration(compensationCtx, id); compensationErr != nil {
				logger.Error("failed to compensate user registration",
					zap.String("user_id", id.String()),
					zap.Error(compensationErr),
				)
				return nil, uuid.Nil, errors.Join(
					fmt.Errorf("create user profile: %w", err),
					fmt.Errorf("compensate user registration: %w", compensationErr),
				)
			}

			logger.Warn("user registration compensated after profile creation failed",
				zap.String("user_id", id.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("create user profile: %w", err)
		}

		result := &models.RegisterResult{
			UserID:        id.String(),
			Email:         user.Email,
			EmailVerified: false,
		}

		logger.Info("user registration successful",
			zap.String("email", id.String()),
			zap.String("username", in.Username),
		)

		return result, id, nil
	})
	if err != nil {
		return nil, err
	}

	return cachedResult[models.RegisterResult](idempotentResult)
}

func (a *AuthServiceStruct) Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("login attempt",
		zap.String("email", in.Email),
		zap.String("client_id", in.ClientID),
		zap.String("ip", in.IP),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("login validation failed",
			zap.String("email", in.Email),
			zap.Error(err),
		)
		return nil, err
	}

	existingUser, err := a.repo.GetUserByEmail(ctx, in.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get user",
			zap.String("email", in.Email),
			zap.Error(err),
		)
		return nil, err
	}

	if existingUser == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("login failed - user not found",
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Login(): %w", models.ErrUserNotFound)
	}

	if !existingUser.IsActive {
		logger.Warn("login failed - user is not active",
			zap.String("user_id", existingUser.ID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Login(): %w", models.ErrUserInactive)
	}
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.PasswordHash), []byte(in.Password))
	if err != nil {
		logger.Warn("login failed - invalid password",
			zap.String("user_id", existingUser.ID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Login(): %w", models.ErrInvalidPassword)
	}

	sessionID, err := a.repo.CreateSession(ctx, &models.Session{
		UserID:    existingUser.ID,
		ClientID:  in.ClientID,
		IP:        in.IP,
		UserAgent: in.UserAgent,
		ExpiresAt: time.Now().Add(refreshTTL),
	})

	if err != nil {
		logger.Error("failed to create session",
			zap.String("user_id", existingUser.ID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	role, err := a.repo.GetRolesByUserID(ctx, existingUser.ID)
	if err != nil {
		a.cleanupFailedLogin(ctx, sessionID, logger)
		logger.Error("failed to get roles for user",
			zap.String("user_id", existingUser.ID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	token, exp, err := a.generateAccessToken(ctx, existingUser.ID, sessionID, role)
	if err != nil {
		a.cleanupFailedLogin(ctx, sessionID, logger)
		logger.Error("failed to generate access token",
			zap.String("user_id", existingUser.ID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	refreshToken, refreshHashToken, expRefresh, err := a.generateRefreshToken(ctx)
	if err != nil {
		a.cleanupFailedLogin(ctx, sessionID, logger)
		logger.Error("failed to generate refresh token",
			zap.String("user_id", existingUser.ID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	refresh := &models.RefreshToken{
		UserID:    existingUser.ID,
		SessionID: sessionID,
		TokenHash: refreshHashToken,
		IsRevoked: false,
		ExpiresAt: time.Unix(expRefresh, 0),
	}

	err = a.repo.CreateToken(ctx, refresh)
	if err != nil {
		a.cleanupFailedLogin(ctx, sessionID, logger)
		logger.Error("failed to create refresh token",
			zap.String("user_id", existingUser.ID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	result := &models.LoginResult{
		AccessToken:          token,
		RefreshToken:         refreshToken,
		AccessExpiresAtUnix:  exp,
		RefreshExpiresAtUnix: expRefresh,
		SessionID:            sessionID,
		TokenType:            "Bearer",
	}

	logger.Info("user logged in successfully",
		zap.String("user_id", existingUser.ID.String()),
		zap.String("session_id", sessionID.String()),
	)

	return result, nil
}

func (a *AuthServiceStruct) Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("refresh tokens",
		zap.String("client_id", in.ClientID),
		zap.String("ip", in.IP),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("refresh validation failed",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, err
	}

	now := time.Now()

	sum := sha256.Sum256([]byte(in.RefreshToken))
	hashRefreshToken := base64.RawURLEncoding.EncodeToString(sum[:])

	refreshToken, err := a.repo.GetByTokenHash(ctx, hashRefreshToken)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get refresh token",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, err
	}

	if refreshToken == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("refresh failed - refresh token not found",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Refresh(): %w", models.ErrInvalidRefreshToken)
	}

	if refreshToken.ExpiresAt.Before(now) {
		logger.Warn("refresh failed - refresh token expired",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Refresh(): %w", models.ErrRefreshTokenExpired)
	}

	if refreshToken.ReplacedByTokenID != nil {
		logger.Warn("refresh failed - refresh token already replaced",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Refresh(): %w", models.ErrRefreshTokenReplaced)
	}

	session, err := a.repo.GetSessionByID(ctx, refreshToken.SessionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get session",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, err
	}

	if session == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("refresh failed - session not found",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Refresh(): %w", models.ErrSessionNotFound)
	}

	if session.IsRevoked || session.UserID != refreshToken.UserID || session.ClientID != in.ClientID {
		logger.Warn("refresh failed - session does not match refresh request",
			zap.String("client_id", in.ClientID),
			zap.String("session_id", refreshToken.SessionID.String()),
		)
		return nil, fmt.Errorf("jwt: Refresh(): %w", models.ErrInvalidRefreshToken)
	}

	if session.ExpiresAt.Before(now) {
		logger.Warn("refresh failed - session expired",
			zap.String("client_id", in.ClientID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: Refresh(): %w", models.ErrSessionExpired)
	}

	roles, err := a.repo.GetRolesByUserID(ctx, refreshToken.UserID)
	if err != nil {
		logger.Error("failed to get roles for user",
			zap.String("user_id", refreshToken.UserID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	accessToken, expAccess, err := a.generateAccessToken(ctx, refreshToken.UserID, refreshToken.SessionID, roles)
	if err != nil {
		logger.Error("failed to generate access token",
			zap.String("user_id", refreshToken.UserID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	newRefreshToken, newHash, expRefresh, err := a.generateRefreshToken(ctx)
	if err != nil {
		logger.Error("failed to generate refresh token",
			zap.String("user_id", refreshToken.UserID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	if sessionExpiry := session.ExpiresAt.Unix(); expRefresh > sessionExpiry {
		expRefresh = sessionExpiry
	}

	refresh := &models.RefreshToken{
		UserID:    refreshToken.UserID,
		SessionID: refreshToken.SessionID,
		TokenHash: newHash,
		IsRevoked: false,
		ExpiresAt: time.Unix(expRefresh, 0),
	}

	err = a.repo.MarkUsedAndReplaceToken(ctx, refreshToken.ID, refresh)
	if err != nil {
		logger.Error("failed to mark used and replaced token",
			zap.String("user_id", refreshToken.UserID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	result := &models.RefreshResult{
		AccessToken:          accessToken,
		RefreshToken:         newRefreshToken,
		AccessExpiresAtUnix:  expAccess,
		RefreshExpiresAtUnix: expRefresh,
		SessionID:            refreshToken.SessionID,
		TokenType:            "Bearer",
	}

	logger.Info("user logged in successfully",
		zap.String("user_id", refreshToken.UserID.String()),
		zap.String("session_id", refreshToken.SessionID.String()),
	)

	return result, nil
}

func (a *AuthServiceStruct) Logout(ctx context.Context, in models.LogoutInput) error {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("logout",
		zap.String("user_id", in.UserID.String()),
		zap.String("session_id", in.SessionID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("logout validation failed",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return err
	}

	session, err := a.repo.GetSessionByID(ctx, in.SessionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get session",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return err
	}
	if session == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("logout failed - session not found",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("jwt: Logout(): %w", models.ErrInvalidSession)
	}
	if session.UserID != in.UserID {
		logger.Warn("logout failed - session belongs to another user",
			zap.String("user_id", in.UserID.String()),
			zap.String("session_id", in.SessionID.String()),
		)
		return fmt.Errorf("jwt: Logout(): %w", models.ErrInvalidSession)
	}

	err = a.repo.Logout(ctx, session.ID)
	if err != nil {
		logger.Error("failed to logout",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return err
	}

	logger.Info("user logged out successfully",
		zap.String("user_id", in.UserID.String()),
		zap.String("session_id", in.SessionID.String()),
	)

	return nil
}

func (a *AuthServiceStruct) cleanupFailedLogin(ctx context.Context, sessionID uuid.UUID, logger *zap.Logger) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := a.repo.Logout(cleanupCtx, sessionID); err != nil {
		logger.Error("failed to clean up session after unsuccessful login",
			zap.String("session_id", sessionID.String()),
			zap.Error(err),
		)
	}
}

func (a *AuthServiceStruct) LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("logoutAll",
		zap.String("user_id", in.UserID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("logoutAll validation failed",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return 0, err
	}

	existingUser, err := a.repo.GetUserByID(ctx, in.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get existing user",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return 0, err
	}
	if existingUser == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("logoutAll failed - user not found",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return 0, fmt.Errorf("jwt: LogoutAll(): %w", models.ErrUserNotFound)
	}

	count, err := a.repo.LogoutAll(ctx, existingUser.ID)
	if err != nil {
		logger.Error("failed to logoutAll",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return 0, err
	}

	logger.Info("user logged out successfully",
		zap.String("user_id", in.UserID.String()),
	)

	return uint32(count), nil

}

func (a *AuthServiceStruct) GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("GetUserAuthInfo",
		zap.String("user_id", userID.String()),
	)

	user, err := a.repo.GetUserByID(ctx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get user",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, err
	}
	if user == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("user not found",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: GetUserAuthInfo(): %w", models.ErrUserNotFound)
	}

	roles, err := a.repo.GetRolesByUserID(ctx, userID)
	if err != nil {
		logger.Error("failed to get roles for user",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	result := &models.UserAuthInfo{
		UserID:        user.ID,
		Email:         user.Email,
		Roles:         roles,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
	}

	logger.Info("user logged in successfully",
		zap.String("user_id", userID.String()),
	)

	return result, nil
}

func (a *AuthServiceStruct) GetJWKS(ctx context.Context) (string, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("Get JWKS")

	publicKey := a.privateKey.Public()

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		logger.Error("failed to parse public key",
			zap.Error(err),
		)
		return "", fmt.Errorf("jwt: GetJWKS(): jwk.FromRaw(): %w", err)
	}

	if err = key.Validate(); err != nil {
		logger.Error("failed to validate public key",
			zap.Error(err),
		)
		return "", fmt.Errorf("jwt: GetJWKS(): key.Validate(): %w", err)
	}

	if err = key.Set(jwk.KeyIDKey, a.keyID); err != nil {
		logger.Error("failed to set jwk key id",
			zap.Error(err),
		)
		return "", fmt.Errorf("jwt: GetJWKS(): key.Set(): KeyIDKey: %w", err)
	}

	if err = key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		logger.Error("failed to set jwk key algorithm",
			zap.Error(err),
		)
		return "", fmt.Errorf("jwt: GetJWKS(): key.Set(): AlgorithmKey: %w", err)
	}

	if err = key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		logger.Error("failed to set jwk key usage",
			zap.Error(err),
		)
		return "", fmt.Errorf("jwt: GetJWKS(): key.Set(): KeyUsageKey: %w", err)
	}

	set := jwk.NewSet()
	if err = set.AddKey(key); err != nil {
		logger.Error("failed to add jwk key",
			zap.Error(err),
		)
		return "", fmt.Errorf("jwt: GetJWKS(): set.AddKey(): %w", err)
	}

	jwkBytes, err := json.Marshal(set)
	if err != nil {
		logger.Error("failed to marshal jwk set",
			zap.Error(err),
		)
		return "", fmt.Errorf("jwt: GetJWKS(): json.Marshal(): %w", err)
	}

	logger.Info("Get JWKS successfully")

	return string(jwkBytes), nil
}

func (a *AuthServiceStruct) ChangePassword(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("ChangePassword",
		zap.String("user_id", in.UserID.String()),
		zap.String("session_id", in.SessionID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("changePassword validation failed",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	idempotentResult, err := a.withIdempotency(ctx, "ChangePassword", in.UserID.String(), in, func(ctx context.Context) (any, uuid.UUID, error) {
		existingUser, err := a.repo.GetUserByID(ctx, in.UserID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("failed to get existing user",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, err
		}
		if existingUser == nil || errors.Is(err, sql.ErrNoRows) {
			logger.Warn("changePassword failed - user not found",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: ChangePassword(): %w", models.ErrUserNotFound)
		}

		err = bcrypt.CompareHashAndPassword([]byte(existingUser.PasswordHash), []byte(in.OldPassword))
		if err != nil {
			logger.Error("failed to compare old password",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: ChangePassword(): %w", models.ErrInvalidOldPassword)
		}

		newHashPassword, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("failed to generate new password",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: ChangePassword(): failed to generate new password: %w", err)
		}

		count, err := a.repo.ChangePassword(ctx, in.UserID, string(newHashPassword), in.SessionID, in.RevokeOtherSessions)
		if err != nil {
			logger.Error("failed to change password",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: ChangePassword(): failed to change password: %w", err)
		}

		result := &models.ChangePasswordResult{
			Success:                  true,
			InvalidatedSessionsCount: count,
		}

		logger.Info("user changed password successfully",
			zap.String("user_id", in.UserID.String()),
			zap.String("session_id", in.SessionID.String()),
		)

		return result, in.UserID, nil
	})
	if err != nil {
		return nil, err
	}

	return cachedResult[models.ChangePasswordResult](idempotentResult)
}

func (a *AuthServiceStruct) SendVerification(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("SendVerification",
		zap.String("user_id", in.UserID.String()),
	)

	if err := in.Validate(); err != nil {
		logger.Warn("sendVerification validation failed",
			zap.String("user_id", in.UserID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	idempotentResult, err := a.withExternalSideEffectIdempotency(ctx, "SendVerification", in.UserID.String(), in, func(ctx context.Context) (any, uuid.UUID, error) {
		user, err := a.repo.GetUserByID(ctx, in.UserID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("failed to get user",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: SendVerificationEmail(): cant get user: %w", err)
		}
		if user == nil || errors.Is(err, sql.ErrNoRows) {
			logger.Warn("sendVerification failed - user not found",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: SendVerificationEmail(): %w", models.ErrUserNotFound)
		}

		if user.EmailVerified {
			logger.Warn("sendVerification failed - email is already verified",
				zap.String("user_id", in.UserID.String()),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: SendVerificationEmail(): %w", models.ErrEmailAlreadyVerified)
		}

		err = a.repo.RevokeUnusedTokensByUserIDAndType(ctx, user.ID, models.TokenTypeEmailVerification)
		if err != nil {
			logger.Error("failed to revoke unused tokens",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: SendVerificationEmail(): cant revoke old verification tokens: %w", err)
		}

		rawToken, hashToken, err := a.generateOpaqueToken(ctx)
		if err != nil {
			logger.Error("failed to generate opaque token",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: SendVerificationEmail(): cant generate token: %w", err)
		}

		expiresAt := time.Now().Add(verifyEmailTTL)

		token := &models.OneTimeToken{
			UserID:    user.ID,
			TokenHash: hashToken,
			Type:      models.TokenTypeEmailVerification,
			ExpiresAt: expiresAt,
		}

		err = a.repo.CreateOneTimeToken(ctx, token)
		if err != nil {
			logger.Error("failed to save opaque token",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: SendVerificationEmail(): cant create verification token: %w", err)
		}

		err = a.mailService.SendVerificationEmail(ctx, user.Email, rawToken)
		if err != nil {
			logger.Error("failed to send verification email",
				zap.String("user_id", in.UserID.String()),
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: SendVerificationEmail(): cant send email: %w", err)
		}

		logger.Info("send verification email successfully",
			zap.String("user_id", in.UserID.String()),
			zap.String("email", in.Email),
		)

		return &models.SendVerificationEmailResult{
			Success:       true,
			ExpiresAtUnix: expiresAt.Unix(),
		}, user.ID, nil
	})
	if err != nil {
		return nil, err
	}

	return cachedResult[models.SendVerificationEmailResult](idempotentResult)
}

func (a *AuthServiceStruct) VerifyEmail(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("VerifyEmail")

	if err := in.Validate(); err != nil {
		logger.Warn("verifyEmail validation failed",
			zap.Error(err),
		)
		return nil, err
	}

	sum := sha256.Sum256([]byte(in.Token))
	hashToken := base64.RawURLEncoding.EncodeToString(sum[:])

	token, err := a.repo.GetOneTimeTokenByHashAndType(ctx, hashToken, models.TokenTypeEmailVerification)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get token by hash",
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: VerifyEmail(): cant get token: %w", err)
	}
	if token == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("verifyEmail failed - token not found")
		return nil, fmt.Errorf("jwt: VerifyEmail(): %w", models.ErrInvalidToken)
	}

	if token.UsedAt != nil {
		logger.Warn("verifyEmail failed - token already used")
		return nil, fmt.Errorf("jwt: VerifyEmail(): %w", models.ErrTokenAlreadyUsed)
	}

	if token.ExpiresAt.Before(time.Now()) {
		logger.Warn("verifyEmail failed - token expired")
		return nil, fmt.Errorf("jwt: VerifyEmail(): %w", models.ErrTokenExpired)
	}

	user, err := a.repo.GetUserByID(ctx, token.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error("failed to get user",
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: VerifyEmail(): cant get user: %w", err)
	}
	if user == nil || errors.Is(err, sql.ErrNoRows) {
		logger.Warn("verifyEmail failed - user not found")
		return nil, fmt.Errorf("jwt: VerifyEmail(): %w", models.ErrUserNotFound)
	}

	err = a.repo.VerifyEmail(ctx, user.ID, token.ID)
	if err != nil {
		logger.Error("failed to verify email",
			zap.Error(err),
		)
		return nil, fmt.Errorf("jwt: VerifyEmail(): verify email tx failed: %w", err)
	}

	logger.Info("verify email successfully",
		zap.String("user_id", user.ID.String()),
	)

	return &models.VerifyEmailResult{
		Success:       true,
		UserID:        user.ID,
		Email:         user.Email,
		EmailVerified: true,
		Message:       "email verified successfully",
	}, nil
}

func (a *AuthServiceStruct) RequestPasswordReset(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("RequestPasswordReset")

	if err := in.Validate(); err != nil {
		logger.Warn("RequestPasswordReset validation failed",
			zap.Error(err),
		)
		return nil, err
	}

	idempotentResult, err := a.withExternalSideEffectIdempotency(ctx, "RequestPasswordReset", in.Email, in, func(ctx context.Context) (any, uuid.UUID, error) {
		user, err := a.repo.GetUserByEmail(ctx, in.Email)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("failed to get user",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: RequestPasswordReset(): cant get user: %w", err)
		}

		if user == nil || errors.Is(err, sql.ErrNoRows) {
			logger.Warn("RequestPasswordReset failed - user not found")

			return &models.RequestPasswordResetResult{
				Success:       true,
				ExpiresAtUnix: 0,
			}, uuid.Nil, nil
		}

		err = a.repo.RevokeUnusedTokensByUserIDAndType(ctx, user.ID, models.TokenTypePasswordReset)
		if err != nil {
			logger.Error("failed to revoke unused tokens",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: RequestPasswordReset(): cant revoke old reset tokens: %w", err)
		}

		rawToken, hashToken, err := a.generateOpaqueToken(ctx)
		if err != nil {
			logger.Error("failed to generate opaque token",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: RequestPasswordReset(): cant generate token: %w", err)
		}

		expiresAt := time.Now().Add(resetPasswordTTL)

		token := &models.OneTimeToken{
			UserID:    user.ID,
			TokenHash: hashToken,
			Type:      models.TokenTypePasswordReset,
			ExpiresAt: expiresAt,
		}

		err = a.repo.CreateOneTimeToken(ctx, token)
		if err != nil {
			logger.Error("failed to save opaque token",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: RequestPasswordReset(): cant create reset token: %w", err)
		}

		err = a.mailService.SendPasswordResetEmail(ctx, user.Email, rawToken)
		if err != nil {
			logger.Error("failed to send reset password",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: RequestPasswordReset(): cant send reset email: %w", err)
		}

		logger.Info("reset email successfully",
			zap.String("user_id", user.ID.String()),
		)

		return &models.RequestPasswordResetResult{
			Success:       true,
			ExpiresAtUnix: expiresAt.Unix(),
		}, user.ID, nil
	})
	if err != nil {
		return nil, err
	}

	return cachedResult[models.RequestPasswordResetResult](idempotentResult)
}

func (a *AuthServiceStruct) ResetPassword(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("ResetPassword")

	if err := in.Validate(); err != nil {
		logger.Warn("ResetPassword validation failed",
			zap.Error(err),
		)
		return nil, err
	}

	idempotentResult, err := a.withIdempotency(ctx, "ResetPassword", "", in, func(ctx context.Context) (any, uuid.UUID, error) {
		sum := sha256.Sum256([]byte(in.Token))
		hashToken := base64.RawURLEncoding.EncodeToString(sum[:])

		token, err := a.repo.GetOneTimeTokenByHashAndType(ctx, hashToken, models.TokenTypePasswordReset)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("failed to get one-time token",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): cant get token: %w", err)
		}
		if token == nil || errors.Is(err, sql.ErrNoRows) {
			logger.Warn("ResetPassword failed - token not found")
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): %w", models.ErrInvalidToken)
		}

		if token.UsedAt != nil {
			logger.Warn("ResetPassword failed - token already used")
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): %w", models.ErrTokenAlreadyUsed)
		}

		if token.ExpiresAt.Before(time.Now()) {
			logger.Warn("ResetPassword failed - token expired")
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): %w", models.ErrTokenExpired)
		}

		user, err := a.repo.GetUserByID(ctx, token.UserID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("failed to get user")
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): cant get user: %w", err)
		}
		if user == nil || errors.Is(err, sql.ErrNoRows) {
			logger.Warn("ResetPassword failed - user not found")
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): %w", models.ErrUserNotFound)
		}

		newHashPassword, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("failed to generate new password",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): cant generate password hash: %w", err)
		}

		count, err := a.repo.ResetPasswordWithToken(ctx, user.ID, string(newHashPassword), token.ID)
		if err != nil {
			logger.Error("failed to reset password",
				zap.Error(err),
			)
			return nil, uuid.Nil, fmt.Errorf("jwt: ResetPassword(): tx reset failed: %w", err)
		}

		logger.Info("reset email successfully",
			zap.String("user_id", user.ID.String()),
		)

		return &models.ResetPasswordResult{
			Success:                  true,
			InvalidatedSessionsCount: count,
		}, user.ID, nil
	})
	if err != nil {
		return nil, err
	}

	return cachedResult[models.ResetPasswordResult](idempotentResult)
}

func (a *AuthServiceStruct) generateAccessToken(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, roles []string) (string, int64, error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("GenerateAccessToken")

	now := time.Now()

	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"sid":   sessionID.String(),
		"roles": roles,
		"exp":   now.Add(ttl).Unix(),
		"iat":   now.Unix(),
		"iss":   "auth-jwt",
		"aud":   "api-gateway",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(a.privateKey)
	if err != nil {
		logger.Error("failed to generate access token",
			zap.Error(err),
		)
		return "", 0, fmt.Errorf("jwt: generateAccessToken: %w", err)
	}

	logger.Info("generate access token successfully")

	return tokenString, now.Add(ttl).Unix(), nil
}

func (a *AuthServiceStruct) generateRefreshToken(ctx context.Context) (raw string, hash string, exp int64, err error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("GenerateRefreshToken")

	b := make([]byte, 32)

	_, err = rand.Read(b)
	if err != nil {
		logger.Error("failed to generate refresh token",
			zap.Error(err),
		)
		return "", "", 0, fmt.Errorf("jwt: generateRefreshToken(): %w", err)
	}

	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = base64.RawURLEncoding.EncodeToString(sum[:])

	logger.Info("generate refresh token successfully")

	return raw, hash, time.Now().Add(refreshTTL).Unix(), nil
}

func (a *AuthServiceStruct) generateOpaqueToken(ctx context.Context) (raw string, hash string, err error) {
	logger := a.logger.With(pkg.RequestIDField(ctx))

	logger.Info("GenerateOpaqueToken")

	b := make([]byte, 32)

	_, err = rand.Read(b)
	if err != nil {
		logger.Error("failed to generate opaque token",
			zap.Error(err),
		)
		return "", "", fmt.Errorf("jwt: generateOpaqueToken(): %w", err)
	}

	raw = base64.RawURLEncoding.EncodeToString(b)

	sum := sha256.Sum256([]byte(raw))
	hash = base64.RawURLEncoding.EncodeToString(sum[:])

	logger.Info("generate opaque token successfully")

	return raw, hash, nil
}
