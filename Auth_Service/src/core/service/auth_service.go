package service

import (
	"auth/models"
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
	"github.com/sirupsen/logrus"
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
}

func NewAuthServiceStruct(repo *repository.Repo, privateKey *rsa.PrivateKey, keyID string, mailService MailService) *AuthServiceStruct {
	return &AuthServiceStruct{repo: repo, privateKey: privateKey, keyID: keyID, mailService: mailService}

}

func (a *AuthServiceStruct) Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	existingUser, err := a.repo.GetUserByEmail(ctx, in.Email)

	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("service: Register(): user with this email already exists")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("service: Register(): cant hash password: %w", err)
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
		return nil, err
	}

	result := &models.RegisterResult{
		UserID:        id.String(),
		Email:         user.Email,
		EmailVerified: false,
	}

	logrus.Printf("Register user with User ID: %s Email: %s", id, in.Email)
	return result, nil
}

func (a *AuthServiceStruct) Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	existingUser, err := a.repo.GetUserByEmail(ctx, in.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if existingUser == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: Login(): user with this email does not exist")
	}

	if !existingUser.IsActive {
		return nil, fmt.Errorf("service: Login(): user is not active")
	}
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.PasswordHash), []byte(in.Password))
	if err != nil {
		return nil, fmt.Errorf("service: Login(): invalid password: %w", err)
	}

	sessionID, err := a.repo.CreateSession(ctx, &models.Session{
		UserID:    existingUser.ID,
		ClientID:  in.ClientID,
		IP:        in.IP,
		UserAgent: in.UserAgent,
		ExpiresAt: time.Now().Add(refreshTTL),
	})

	if err != nil {
		return nil, err
	}

	role, err := a.repo.GetRolesByUserID(ctx, existingUser.ID)
	if err != nil {
		return nil, err
	}

	token, exp, err := a.generateAccessToken(existingUser.ID, sessionID, role)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshHashToken, expRefresh, err := a.generateRefreshToken()
	if err != nil {
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
	return result, nil
}

func (a *AuthServiceStruct) Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	now := time.Now()

	sum := sha256.Sum256([]byte(in.RefreshToken))
	hashRefreshToken := base64.RawURLEncoding.EncodeToString(sum[:])

	refreshToken, err := a.repo.GetByTokenHash(ctx, hashRefreshToken)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if refreshToken == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: Refresh(): invalid refresh token")
	}

	if refreshToken.ExpiresAt.Before(now) {
		return nil, fmt.Errorf("service: Refresh(): invalid refresh token, token has expired")
	}

	if refreshToken.ReplacedByTokenID != nil {
		return nil, fmt.Errorf("service: Refresh(): invalid refresh token, token has been replaced")
	}

	session, err := a.repo.GetSessionByID(ctx, refreshToken.SessionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if session == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: Refresh(): invalid refresh token, session does not exist")
	}

	if session.ExpiresAt.Before(now) {
		return nil, fmt.Errorf("service: Refresh(): invalid refresh token, session has expired")
	}

	roles, err := a.repo.GetRolesByUserID(ctx, refreshToken.UserID)
	if err != nil {
		return nil, err
	}

	accessToken, expAccess, err := a.generateAccessToken(refreshToken.UserID, refreshToken.SessionID, roles)
	if err != nil {
		return nil, err
	}

	newRefreshToken, newHash, expRefresh, err := a.generateRefreshToken()
	if err != nil {
		return nil, err
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
	return result, nil
}

func (a *AuthServiceStruct) Logout(ctx context.Context, in models.LogoutInput) error {

	if err := in.Validate(); err != nil {
		return err
	}

	session, err := a.repo.GetSessionByID(ctx, in.SessionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if session == nil || errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("service: Logout(): invalid session")
	}

	err = a.repo.Logout(ctx, session.ID)
	if err != nil {
		return err
	}

	logrus.Printf("service: Logout(): session removed")

	return nil
}

func (a *AuthServiceStruct) LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error) {

	if err := in.Validate(); err != nil {
		return 0, err
	}

	existingUser, err := a.repo.GetUserByID(ctx, in.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if existingUser == nil || errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("service: LogoutAll(): invalid user")
	}

	count, err := a.repo.LogoutAll(ctx, existingUser.ID)
	if err != nil {
		return 0, err
	}

	logrus.Printf("LogoutAll(): revoked %d sessions", count)
	return uint32(count), nil

}

func (a *AuthServiceStruct) GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error) {

	user, err := a.repo.GetUserByID(ctx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if user == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: GetUserAuthInfo(): invalid user")
	}

	roles, err := a.repo.GetRolesByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := &models.UserAuthInfo{
		UserID:        user.ID,
		Email:         user.Email,
		Roles:         roles,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
	}

	return result, nil
}

func (a *AuthServiceStruct) GetJWKS(ctx context.Context) (string, error) {
	publicKey := a.privateKey.Public()

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		return "", fmt.Errorf("service: GetJWKS(): jwk.FromRaw(): %w", err)
	}

	if err = key.Validate(); err != nil {
		return "", fmt.Errorf("service: GetJWKS(): key.Validate(): %w", err)
	}

	if err = key.Set(jwk.KeyIDKey, a.keyID); err != nil {
		return "", fmt.Errorf("service: GetJWKS(): key.Set(): KeyIDKey: %w", err)
	}

	if err = key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return "", fmt.Errorf("service: GetJWKS(): key.Set(): AlgorithmKey: %w", err)
	}

	if err = key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return "", fmt.Errorf("service: GetJWKS(): key.Set(): KeyUsageKey: %w", err)
	}

	set := jwk.NewSet()
	if err = set.AddKey(key); err != nil {
		return "", fmt.Errorf("service: GetJWKS(): set.AddKey(): %w", err)
	}

	jwkBytes, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("service: GetJWKS(): json.Marshal(): %w", err)
	}

	return string(jwkBytes), nil
}

func (a *AuthServiceStruct) ChangePassword(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	existingUser, err := a.repo.GetUserByID(ctx, in.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if existingUser == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: ChangePassword(): user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUser.PasswordHash), []byte(in.OldPassword))
	if err != nil {
		return nil, fmt.Errorf("service: ChangePassword(): invalid old password")
	}

	newHashPassword, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("service: ChangePassword(): failed to generate new password: %w", err)
	}

	count, err := a.repo.ChangePassword(ctx, in.UserID, string(newHashPassword), in.SessionID, in.RevokeOtherSessions)
	if err != nil {
		return nil, fmt.Errorf("service: ChangePassword(): failed to change password: %w", err)
	}

	result := &models.ChangePasswordResult{
		Success:                  true,
		InvalidatedSessionsCount: count,
	}
	return result, nil

}

func (a *AuthServiceStruct) SendVerification(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	user, err := a.repo.GetUserByID(ctx, in.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: SendVerificationEmail(): cant get user: %w", err)
	}
	if user == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: SendVerificationEmail(): user not found")
	}

	if user.EmailVerified {
		return nil, fmt.Errorf("service: SendVerificationEmail(): email already verified")
	}

	err = a.repo.RevokeUnusedTokensByUserIDAndType(ctx, user.ID, models.TokenTypeEmailVerification)
	if err != nil {
		return nil, fmt.Errorf("service: SendVerificationEmail(): cant revoke old verification tokens: %w", err)
	}

	rawToken, hashToken, err := a.generateOpaqueToken()
	if err != nil {
		return nil, fmt.Errorf("service: SendVerificationEmail(): cant generate token: %w", err)
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
		return nil, fmt.Errorf("service: SendVerificationEmail(): cant create verification token: %w", err)
	}

	err = a.mailService.SendVerificationEmail(ctx, user.Email, rawToken)
	if err != nil {
		return nil, fmt.Errorf("service: SendVerificationEmail(): cant send email: %w", err)
	}

	return &models.SendVerificationEmailResult{
		Success:       true,
		ExpiresAtUnix: expiresAt.Unix(),
	}, nil
}

func (a *AuthServiceStruct) VerifyEmail(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	sum := sha256.Sum256([]byte(in.Token))
	hashToken := base64.RawURLEncoding.EncodeToString(sum[:])

	token, err := a.repo.GetOneTimeTokenByHashAndType(ctx, hashToken, models.TokenTypeEmailVerification)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: VerifyEmail(): cant get token: %w", err)
	}
	if token == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: VerifyEmail(): invalid token")
	}

	if token.UsedAt != nil {
		return nil, fmt.Errorf("service: VerifyEmail(): token already used")
	}

	if token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("service: VerifyEmail(): token expired")
	}

	user, err := a.repo.GetUserByID(ctx, token.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: VerifyEmail(): cant get user: %w", err)
	}
	if user == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: VerifyEmail(): user not found")
	}

	user.EmailVerified = true

	err = a.repo.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("service: VerifyEmail(): cant update user: %w", err)
	}

	err = a.repo.MarkOneTimeTokenUsed(ctx, token.ID)
	if err != nil {
		return nil, fmt.Errorf("service: VerifyEmail(): cant mark token used: %w", err)
	}

	return &models.VerifyEmailResult{
		Success:       true,
		UserID:        user.ID,
		Email:         user.Email,
		EmailVerified: true,
		Message:       "email verified successfully",
	}, nil
}

func (a *AuthServiceStruct) RequestPasswordReset(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	user, err := a.repo.GetUserByEmail(ctx, in.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: RequestPasswordReset(): cant get user: %w", err)
	}

	if user == nil || errors.Is(err, sql.ErrNoRows) {
		return &models.RequestPasswordResetResult{
			Success:       true,
			ExpiresAtUnix: 0,
		}, nil
	}

	err = a.repo.RevokeUnusedTokensByUserIDAndType(ctx, user.ID, models.TokenTypePasswordReset)
	if err != nil {
		return nil, fmt.Errorf("service: RequestPasswordReset(): cant revoke old reset tokens: %w", err)
	}

	rawToken, hashToken, err := a.generateOpaqueToken()
	if err != nil {
		return nil, fmt.Errorf("service: RequestPasswordReset(): cant generate token: %w", err)
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
		return nil, fmt.Errorf("service: RequestPasswordReset(): cant create reset token: %w", err)
	}

	err = a.mailService.SendPasswordResetEmail(ctx, user.Email, rawToken)
	if err != nil {
		return nil, fmt.Errorf("service: RequestPasswordReset(): cant send reset email: %w", err)
	}

	return &models.RequestPasswordResetResult{
		Success:       true,
		ExpiresAtUnix: expiresAt.Unix(),
	}, nil
}

func (a *AuthServiceStruct) ResetPassword(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}
	
	sum := sha256.Sum256([]byte(in.Token))
	hashToken := base64.RawURLEncoding.EncodeToString(sum[:])

	token, err := a.repo.GetOneTimeTokenByHashAndType(ctx, hashToken, models.TokenTypePasswordReset)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: ResetPassword(): cant get token: %w", err)
	}
	if token == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: ResetPassword(): invalid token")
	}

	if token.UsedAt != nil {
		return nil, fmt.Errorf("service: ResetPassword(): token already used")
	}

	if token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("service: ResetPassword(): token expired")
	}

	user, err := a.repo.GetUserByID(ctx, token.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: ResetPassword(): cant get user: %w", err)
	}
	if user == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: ResetPassword(): user not found")
	}

	newHashPassword, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("service: ResetPassword(): cant generate password hash: %w", err)
	}

	count, err := a.repo.ResetPassword(ctx, user.ID, string(newHashPassword))
	if err != nil {
		return nil, fmt.Errorf("service: ResetPassword(): tx reset failed: %w", err)
	}

	err = a.repo.MarkOneTimeTokenUsed(ctx, token.ID)
	if err != nil {
		return nil, fmt.Errorf("service: ResetPassword(): cant mark token used: %w", err)
	}

	return &models.ResetPasswordResult{
		Success:                  true,
		InvalidatedSessionsCount: count,
	}, nil
}

func (a *AuthServiceStruct) generateAccessToken(userID uuid.UUID, sessionID uuid.UUID, roles []string) (string, int64, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"sid":   sessionID.String(),
		"roles": roles,
		"exp":   now.Add(ttl).Unix(),
		"iat":   now.Unix(),
		"iss":   "auth-service",
		"aud":   "api-gateway",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("service: generateAccessToken: %w", err)
	}

	return tokenString, now.Add(ttl).Unix(), nil
}

func (a *AuthServiceStruct) generateRefreshToken() (raw string, hash string, exp int64, err error) {
	b := make([]byte, 32)

	_, err = rand.Read(b)
	if err != nil {
		return "", "", 0, fmt.Errorf("service: generateRefreshToken(): %w", err)
	}

	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = base64.RawURLEncoding.EncodeToString(sum[:])
	return raw, hash, time.Now().Add(refreshTTL).Unix(), nil
}

func (a *AuthServiceStruct) generateOpaqueToken() (raw string, hash string, err error) {
	b := make([]byte, 32)

	_, err = rand.Read(b)
	if err != nil {
		return "", "", fmt.Errorf("service: generateOpaqueToken(): %w", err)
	}

	raw = base64.RawURLEncoding.EncodeToString(b)

	sum := sha256.Sum256([]byte(raw))
	hash = base64.RawURLEncoding.EncodeToString(sum[:])

	return raw, hash, nil
}
