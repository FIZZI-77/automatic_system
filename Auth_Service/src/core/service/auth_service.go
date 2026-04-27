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
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"time"
)

const salt = "dfg4124321jndfsglorprmupgreuhg"
const ttl = time.Minute * 15
const refreshTTL = time.Hour * 24 * 30

type AuthServiceStruct struct {
	repo       *repository.Repo
	privateKey *rsa.PrivateKey
}

func NewAuthServiceStruct(repo *repository.Repo, privateKey *rsa.PrivateKey) *AuthServiceStruct {
	return &AuthServiceStruct{repo: repo, privateKey: privateKey}

}

func (a *AuthServiceStruct) Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error) {
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
	existingUser, err := a.repo.GetUserByEmail(ctx, in.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if existingUser == nil || errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service: Login(): user with this email does not exist")
	}

	if !existingUser.IsActive {
		return nil, fmt.Errorf("service: Login(): user with this email does not exist")
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

	now := time.Now()

	sum := sha256.Sum256([]byte(in.RefreshToken))
	hashRefreshToken := base64.URLEncoding.EncodeToString(sum[:])

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

}

func (a *AuthServiceStruct) LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error) {

}

func (a *AuthServiceStruct) GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error) {

}

func (a *AuthServiceStruct) GetJWKS(ctx context.Context) (string, error) {

}

func (a *AuthServiceStruct) generateAccessToken(userID uuid.UUID, sessionID uuid.UUID, role []string) (string, int64, error) {
	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"sid":   sessionID.String(),
		"roles": role,
		"exp":   time.Now().Add(ttl).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   "auth-service",
		"aud":   "api gateway",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("service: GenerateToken(): %w", err)
	}

	return tokenString, time.Now().Add(ttl).Unix(), nil
}

func (a *AuthServiceStruct) generateRefreshToken() (raw string, hash string, exp int64, err error) {
	b := make([]byte, 32)

	_, err = rand.Read(b)
	if err != nil {
		return "", "", 0, fmt.Errorf("service: generateRefreshToken(): %w", err)
	}

	raw = base64.URLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = base64.URLEncoding.EncodeToString(sum[:])
	return raw, hash, time.Now().Add(refreshTTL).Unix(), nil
}
