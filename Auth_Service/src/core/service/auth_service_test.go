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
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"testing"
	"time"
)

type mockUserRepo struct {
	createUserFunc     func(ctx context.Context, user *models.User) (uuid.UUID, error)
	getUserByIDFunc    func(ctx context.Context, id uuid.UUID) (*models.User, error)
	getUserByEmailFunc func(ctx context.Context, email string) (*models.User, error)
	updateUserFunc     func(ctx context.Context, user *models.User) error
}

func (m *mockUserRepo) CreateUser(ctx context.Context, user *models.User) (uuid.UUID, error) {
	return m.createUserFunc(ctx, user)
}

func (m *mockUserRepo) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return m.getUserByIDFunc(ctx, id)
}

func (m *mockUserRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return m.getUserByEmailFunc(ctx, email)
}

func (m *mockUserRepo) UpdateUser(ctx context.Context, user *models.User) error {
	return m.updateUserFunc(ctx, user)
}

type mockSessionRepo struct {
	createSessionFunc            func(ctx context.Context, session *models.Session) (uuid.UUID, error)
	getSessionByIDFunc           func(ctx context.Context, id uuid.UUID) (*models.Session, error)
	getSessionByUserIDFunc       func(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	revokeSessionByIDFunc        func(ctx context.Context, sessionID uuid.UUID) error
	revokeAllSessionByUserIDFunc func(ctx context.Context, userID uuid.UUID) (int64, error)
	updateLastSeenSessionFunc    func(ctx context.Context, sessionID uuid.UUID) error
}

func (m *mockSessionRepo) CreateSession(ctx context.Context, session *models.Session) (uuid.UUID, error) {
	return m.createSessionFunc(ctx, session)
}

func (m *mockSessionRepo) GetSessionByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	return m.getSessionByIDFunc(ctx, id)
}

func (m *mockSessionRepo) GetSessionByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	return m.getSessionByUserIDFunc(ctx, userID)
}

func (m *mockSessionRepo) RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error {
	return m.revokeSessionByIDFunc(ctx, sessionID)
}

func (m *mockSessionRepo) RevokeAllSessionByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	return m.revokeAllSessionByUserIDFunc(ctx, userID)
}

func (m *mockSessionRepo) UpdateLastSeenSession(ctx context.Context, sessionID uuid.UUID) error {
	return m.updateLastSeenSessionFunc(ctx, sessionID)
}

type mockRefreshTokenRepo struct {
	createTokenFunc             func(ctx context.Context, token *models.RefreshToken) error
	getByTokenHashFunc          func(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	revokeTokenByIDFunc         func(ctx context.Context, tokenID uuid.UUID) error
	revokeTokenBySessionIDFunc  func(ctx context.Context, sessionID uuid.UUID) error
	revokeAllTokenByUserIDFunc  func(ctx context.Context, userID uuid.UUID) error
	markUsedAndReplaceTokenFunc func(ctx context.Context, oldTokenID uuid.UUID, newToken *models.RefreshToken) error
}

func (m *mockRefreshTokenRepo) CreateToken(ctx context.Context, token *models.RefreshToken) error {
	return m.createTokenFunc(ctx, token)
}

func (m *mockRefreshTokenRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	return m.getByTokenHashFunc(ctx, tokenHash)
}

func (m *mockRefreshTokenRepo) RevokeTokenByID(ctx context.Context, tokenID uuid.UUID) error {
	return m.revokeTokenByIDFunc(ctx, tokenID)
}

func (m *mockRefreshTokenRepo) RevokeTokenBySessionID(ctx context.Context, sessionID uuid.UUID) error {
	return m.revokeTokenBySessionIDFunc(ctx, sessionID)
}

func (m *mockRefreshTokenRepo) RevokeAllTokenByUserID(ctx context.Context, userID uuid.UUID) error {
	return m.revokeAllTokenByUserIDFunc(ctx, userID)
}

func (m *mockRefreshTokenRepo) MarkUsedAndReplaceToken(ctx context.Context, oldTokenID uuid.UUID, newToken *models.RefreshToken) error {
	return m.markUsedAndReplaceTokenFunc(ctx, oldTokenID, newToken)
}

type mockRoleRepo struct {
	getRolesByUserIDFunc func(ctx context.Context, userID uuid.UUID) ([]string, error)
	assignRoleToUserFunc func(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error
}

func (m *mockRoleRepo) GetRolesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return m.getRolesByUserIDFunc(ctx, userID)
}

func (m *mockRoleRepo) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error {
	return m.assignRoleToUserFunc(ctx, userID, roleID)
}

type mockTXRepo struct {
	changePasswordFunc func(ctx context.Context, userID uuid.UUID, password string, sessionID uuid.UUID, revokeOtherSessions bool) (int32, error)
	logoutFunc         func(ctx context.Context, sessionID uuid.UUID) error
	logoutAllFunc      func(ctx context.Context, userID uuid.UUID) (int64, error)
	resetPasswordFunc  func(ctx context.Context, userID uuid.UUID, passwordHash string) (int32, error)
}

func (m *mockTXRepo) ChangePassword(ctx context.Context, userID uuid.UUID, password string, sessionID uuid.UUID, revokeOtherSessions bool) (int32, error) {
	return m.changePasswordFunc(ctx, userID, password, sessionID, revokeOtherSessions)
}

func (m *mockTXRepo) Logout(ctx context.Context, sessionID uuid.UUID) error {
	return m.logoutFunc(ctx, sessionID)
}

func (m *mockTXRepo) LogoutAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	return m.logoutAllFunc(ctx, userID)
}

func (m *mockTXRepo) ResetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) (int32, error) {
	return m.resetPasswordFunc(ctx, userID, passwordHash)
}

type mockOneTimeTokenRepo struct {
	createOneTimeTokenFunc                func(ctx context.Context, token *models.OneTimeToken) error
	getOneTimeTokenByHashAndTypeFunc      func(ctx context.Context, tokenHash string, tokenType models.TokenType) (*models.OneTimeToken, error)
	markOneTimeTokenUsedFunc              func(ctx context.Context, tokenID uuid.UUID) error
	revokeUnusedTokensByUserIDAndTypeFunc func(ctx context.Context, userID uuid.UUID, tokenType models.TokenType) error
}

func (m *mockOneTimeTokenRepo) CreateOneTimeToken(ctx context.Context, token *models.OneTimeToken) error {
	return m.createOneTimeTokenFunc(ctx, token)
}

func (m *mockOneTimeTokenRepo) GetOneTimeTokenByHashAndType(ctx context.Context, tokenHash string, tokenType models.TokenType) (*models.OneTimeToken, error) {
	return m.getOneTimeTokenByHashAndTypeFunc(ctx, tokenHash, tokenType)
}

func (m *mockOneTimeTokenRepo) MarkOneTimeTokenUsed(ctx context.Context, tokenID uuid.UUID) error {
	return m.markOneTimeTokenUsedFunc(ctx, tokenID)
}

func (m *mockOneTimeTokenRepo) RevokeUnusedTokensByUserIDAndType(ctx context.Context, userID uuid.UUID, tokenType models.TokenType) error {
	return m.revokeUnusedTokensByUserIDAndTypeFunc(ctx, userID, tokenType)
}

type mockMailService struct {
	sendVerificationEmailFunc  func(ctx context.Context, toEmail string, token string) error
	sendPasswordResetEmailFunc func(ctx context.Context, toEmail string, token string) error
}

func (m *mockMailService) SendVerificationEmail(ctx context.Context, toEmail string, token string) error {
	return m.sendVerificationEmailFunc(ctx, toEmail, token)
}

func (m *mockMailService) SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error {
	return m.sendPasswordResetEmailFunc(ctx, toEmail, token)
}

func newTestPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	return key
}

func newTestService(repo *repository.Repo, mail MailService, t *testing.T) *AuthServiceStruct {
	t.Helper()

	return NewAuthServiceStruct(
		repo,
		newTestPrivateKey(t),
		"test-key-id",
		mail,
		zap.NewNop(),
	)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestAuthService_Register_Success(t *testing.T) {
	userID := uuid.New()

	userRepo := &mockUserRepo{
		getUserByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			if email != "test@example.com" {
				t.Fatalf("expected email test@example.com, got %s", email)
			}

			return nil, sql.ErrNoRows
		},
		createUserFunc: func(ctx context.Context, user *models.User) (uuid.UUID, error) {
			if user.Email != "test@example.com" {
				t.Fatalf("expected email test@example.com, got %s", user.Email)
			}

			if user.Username != "testuser" {
				t.Fatalf("expected username testuser, got %s", user.Username)
			}

			if user.PasswordHash == "" {
				t.Fatal("expected password hash")
			}

			if !user.IsActive {
				t.Fatal("expected user active")
			}

			if user.EmailVerified {
				t.Fatal("expected email not verified")
			}

			return userID, nil
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Register(context.Background(), models.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Username: "testuser",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.UserID != userID.String() {
		t.Fatalf("expected user id %s, got %s", userID.String(), result.UserID)
	}

	if result.Email != "test@example.com" {
		t.Fatalf("expected email test@example.com, got %s", result.Email)
	}

	if result.EmailVerified {
		t.Fatal("expected email verified false")
	}
}

func TestAuthService_Register_UserAlreadyExists(t *testing.T) {
	existingUser := &models.User{
		ID:    uuid.New(),
		Email: "test@example.com",
	}

	userRepo := &mockUserRepo{
		getUserByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return existingUser, nil
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Register(context.Background(), models.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Username: "testuser",
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthService_Register_InvalidInput(t *testing.T) {
	repo := &repository.Repo{}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Register(context.Background(), models.RegisterInput{
		Email:    "",
		Password: "",
		Username: "",
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestAuthService_Login_Success(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userRepo := &mockUserRepo{
		getUserByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return &models.User{
				ID:           userID,
				Email:        email,
				Username:     "testuser",
				PasswordHash: string(passwordHash),
				IsActive:     true,
			}, nil
		},
	}

	sessionRepo := &mockSessionRepo{
		createSessionFunc: func(ctx context.Context, session *models.Session) (uuid.UUID, error) {
			if session.UserID != userID {
				t.Fatalf("expected user id %s, got %s", userID, session.UserID)
			}

			if session.ClientID != "web-client" {
				t.Fatalf("expected client id web-client, got %s", session.ClientID)
			}

			return sessionID, nil
		},
	}

	roleRepo := &mockRoleRepo{
		getRolesByUserIDFunc: func(ctx context.Context, id uuid.UUID) ([]string, error) {
			if id != userID {
				t.Fatalf("expected user id %s, got %s", userID, id)
			}

			return []string{"user"}, nil
		},
	}

	refreshRepo := &mockRefreshTokenRepo{
		createTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			if token.UserID != userID {
				t.Fatalf("expected user id %s, got %s", userID, token.UserID)
			}

			if token.SessionID != sessionID {
				t.Fatalf("expected session id %s, got %s", sessionID, token.SessionID)
			}

			if token.TokenHash == "" {
				t.Fatal("expected token hash")
			}

			return nil
		},
	}

	repo := &repository.Repo{
		UserRepository:         userRepo,
		SessionRepository:      sessionRepo,
		RoleRepository:         roleRepo,
		RefreshTokenRepository: refreshRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Login(context.Background(), models.LoginInput{
		Email:     "test@example.com",
		Password:  "password123",
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "Mozilla/5.0",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.AccessToken == "" {
		t.Fatal("expected access token")
	}

	if result.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}

	if result.SessionID != sessionID {
		t.Fatalf("expected session id %s, got %s", sessionID, result.SessionID)
	}

	if result.TokenType != "Bearer" {
		t.Fatalf("expected Bearer, got %s", result.TokenType)
	}
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	userRepo := &mockUserRepo{
		getUserByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return nil, sql.ErrNoRows
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Login(context.Background(), models.LoginInput{
		Email:     "test@example.com",
		Password:  "password123",
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "Mozilla/5.0",
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthService_Login_InvalidPassword(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userRepo := &mockUserRepo{
		getUserByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return &models.User{
				ID:           uuid.New(),
				Email:        email,
				PasswordHash: string(passwordHash),
				IsActive:     true,
			}, nil
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Login(context.Background(), models.LoginInput{
		Email:     "test@example.com",
		Password:  "wrong-password",
		ClientID:  "web-client",
		IP:        "127.0.0.1",
		UserAgent: "Mozilla/5.0",
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthService_Refresh_Success(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	oldTokenID := uuid.New()
	rawRefreshToken := "old-refresh-token"
	oldHash := hashToken(rawRefreshToken)

	refreshRepo := &mockRefreshTokenRepo{
		getByTokenHashFunc: func(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
			if tokenHash != oldHash {
				t.Fatalf("expected hash %s, got %s", oldHash, tokenHash)
			}

			return &models.RefreshToken{
				ID:        oldTokenID,
				UserID:    userID,
				SessionID: sessionID,
				TokenHash: oldHash,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		markUsedAndReplaceTokenFunc: func(ctx context.Context, tokenID uuid.UUID, newToken *models.RefreshToken) error {
			if tokenID != oldTokenID {
				t.Fatalf("expected old token id %s, got %s", oldTokenID, tokenID)
			}

			if newToken.UserID != userID {
				t.Fatalf("expected user id %s, got %s", userID, newToken.UserID)
			}

			if newToken.SessionID != sessionID {
				t.Fatalf("expected session id %s, got %s", sessionID, newToken.SessionID)
			}

			if newToken.TokenHash == "" {
				t.Fatal("expected new token hash")
			}

			return nil
		},
	}

	sessionRepo := &mockSessionRepo{
		getSessionByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Session, error) {
			if id != sessionID {
				t.Fatalf("expected session id %s, got %s", sessionID, id)
			}

			return &models.Session{
				ID:        sessionID,
				UserID:    userID,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}

	roleRepo := &mockRoleRepo{
		getRolesByUserIDFunc: func(ctx context.Context, id uuid.UUID) ([]string, error) {
			return []string{"user"}, nil
		},
	}

	repo := &repository.Repo{
		RefreshTokenRepository: refreshRepo,
		SessionRepository:      sessionRepo,
		RoleRepository:         roleRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Refresh(context.Background(), models.RefreshInput{
		RefreshToken: rawRefreshToken,
		ClientID:     "web-client",
		IP:           "127.0.0.1",
		UserAgent:    "Mozilla/5.0",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.AccessToken == "" {
		t.Fatal("expected access token")
	}

	if result.RefreshToken == "" {
		t.Fatal("expected new refresh token")
	}

	if result.SessionID != sessionID {
		t.Fatalf("expected session id %s, got %s", sessionID, result.SessionID)
	}

	if result.TokenType != "Bearer" {
		t.Fatalf("expected Bearer, got %s", result.TokenType)
	}
}

func TestAuthService_Refresh_TokenNotFound(t *testing.T) {
	refreshRepo := &mockRefreshTokenRepo{
		getByTokenHashFunc: func(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
			return nil, sql.ErrNoRows
		},
	}

	repo := &repository.Repo{
		RefreshTokenRepository: refreshRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.Refresh(context.Background(), models.RefreshInput{
		RefreshToken: "bad-token",
		ClientID:     "web-client",
		IP:           "127.0.0.1",
		UserAgent:    "Mozilla/5.0",
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthService_Logout_Success(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	sessionRepo := &mockSessionRepo{
		getSessionByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Session, error) {
			return &models.Session{
				ID:     sessionID,
				UserID: userID,
			}, nil
		},
	}

	txRepo := &mockTXRepo{
		logoutFunc: func(ctx context.Context, id uuid.UUID) error {
			if id != sessionID {
				t.Fatalf("expected session id %s, got %s", sessionID, id)
			}

			return nil
		},
	}

	repo := &repository.Repo{
		SessionRepository: sessionRepo,
		TXRepository:      txRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	err := svc.Logout(context.Background(), models.LogoutInput{
		UserID:    userID,
		SessionID: sessionID,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestAuthService_Logout_SessionNotFound(t *testing.T) {
	sessionRepo := &mockSessionRepo{
		getSessionByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Session, error) {
			return nil, sql.ErrNoRows
		},
	}

	repo := &repository.Repo{
		SessionRepository: sessionRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	err := svc.Logout(context.Background(), models.LogoutInput{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
	})

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthService_LogoutAll_Success(t *testing.T) {
	userID := uuid.New()

	userRepo := &mockUserRepo{
		getUserByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{
				ID:    userID,
				Email: "test@example.com",
			}, nil
		},
	}

	txRepo := &mockTXRepo{
		logoutAllFunc: func(ctx context.Context, id uuid.UUID) (int64, error) {
			if id != userID {
				t.Fatalf("expected user id %s, got %s", userID, id)
			}

			return 3, nil
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
		TXRepository:   txRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	count, err := svc.LogoutAll(context.Background(), models.LogoutAllInput{
		UserID: userID,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if count != 3 {
		t.Fatalf("expected count 3, got %d", count)
	}
}

func TestAuthService_GetUserAuthInfo_Success(t *testing.T) {
	userID := uuid.New()

	userRepo := &mockUserRepo{
		getUserByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{
				ID:            userID,
				Email:         "test@example.com",
				IsActive:      true,
				EmailVerified: true,
			}, nil
		},
	}

	roleRepo := &mockRoleRepo{
		getRolesByUserIDFunc: func(ctx context.Context, id uuid.UUID) ([]string, error) {
			return []string{"user", "admin"}, nil
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
		RoleRepository: roleRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.GetUserAuthInfo(context.Background(), userID)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, result.UserID)
	}

	if result.Email != "test@example.com" {
		t.Fatalf("expected email test@example.com, got %s", result.Email)
	}

	if len(result.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(result.Roles))
	}

	if !result.IsActive {
		t.Fatal("expected active user")
	}

	if !result.EmailVerified {
		t.Fatal("expected email verified")
	}
}

func TestAuthService_GetJWKS_Success(t *testing.T) {
	repo := &repository.Repo{}

	svc := newTestService(repo, &mockMailService{}, t)

	jwks, err := svc.GetJWKS(context.Background())

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if jwks == "" {
		t.Fatal("expected jwks json")
	}
}

func TestAuthService_ChangePassword_Success(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	oldHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userRepo := &mockUserRepo{
		getUserByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{
				ID:           userID,
				PasswordHash: string(oldHash),
			}, nil
		},
	}

	txRepo := &mockTXRepo{
		changePasswordFunc: func(ctx context.Context, id uuid.UUID, password string, sid uuid.UUID, revokeOtherSessions bool) (int32, error) {
			if id != userID {
				t.Fatalf("expected user id %s, got %s", userID, id)
			}

			if sid != sessionID {
				t.Fatalf("expected session id %s, got %s", sessionID, sid)
			}

			if password == "" {
				t.Fatal("expected new password hash")
			}

			if !revokeOtherSessions {
				t.Fatal("expected revoke other sessions true")
			}

			return 2, nil
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
		TXRepository:   txRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.ChangePassword(context.Background(), models.ChangePasswordInput{
		UserID:              userID,
		SessionID:           sessionID,
		OldPassword:         "old-password",
		NewPassword:         "new-password",
		RevokeOtherSessions: true,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected success true")
	}

	if result.InvalidatedSessionsCount != 2 {
		t.Fatalf("expected 2 invalidated sessions, got %d", result.InvalidatedSessionsCount)
	}
}

func TestAuthService_ChangePassword_InvalidOldPassword(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	oldHash, err := bcrypt.GenerateFromPassword([]byte("correct-old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userRepo := &mockUserRepo{
		getUserByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{
				ID:           userID,
				PasswordHash: string(oldHash),
			}, nil
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.ChangePassword(context.Background(), models.ChangePasswordInput{
		UserID:      userID,
		SessionID:   sessionID,
		OldPassword: "wrong-old-password",
		NewPassword: "new-password",
	})

	if result != nil {
		t.Fatal("expected nil result")
	}

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthService_SendVerification_Success(t *testing.T) {
	userID := uuid.New()

	userRepo := &mockUserRepo{
		getUserByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{
				ID:            userID,
				Email:         "test@example.com",
				EmailVerified: false,
			}, nil
		},
	}

	oneTimeRepo := &mockOneTimeTokenRepo{
		revokeUnusedTokensByUserIDAndTypeFunc: func(ctx context.Context, id uuid.UUID, tokenType models.TokenType) error {
			if id != userID {
				t.Fatalf("expected user id %s, got %s", userID, id)
			}

			if tokenType != models.TokenTypeEmailVerification {
				t.Fatalf("expected email verification token type, got %s", tokenType)
			}

			return nil
		},
		createOneTimeTokenFunc: func(ctx context.Context, token *models.OneTimeToken) error {
			if token.UserID != userID {
				t.Fatalf("expected user id %s, got %s", userID, token.UserID)
			}

			if token.TokenHash == "" {
				t.Fatal("expected token hash")
			}

			if token.Type != models.TokenTypeEmailVerification {
				t.Fatalf("expected email verification token type, got %s", token.Type)
			}

			return nil
		},
	}

	mail := &mockMailService{
		sendVerificationEmailFunc: func(ctx context.Context, toEmail string, token string) error {
			if toEmail != "test@example.com" {
				t.Fatalf("expected email test@example.com, got %s", toEmail)
			}

			if token == "" {
				t.Fatal("expected raw token")
			}

			return nil
		},
	}

	repo := &repository.Repo{
		UserRepository:   userRepo,
		OneTimeTokenRepo: oneTimeRepo,
	}

	svc := newTestService(repo, mail, t)

	result, err := svc.SendVerification(context.Background(), models.SendVerificationEmailInput{
		UserID: userID,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected success true")
	}

	if result.ExpiresAtUnix == 0 {
		t.Fatal("expected expires_at_unix")
	}
}

func TestAuthService_VerifyEmail_Success(t *testing.T) {
	userID := uuid.New()
	tokenID := uuid.New()
	rawToken := "verify-token"
	hash := hashToken(rawToken)

	oneTimeRepo := &mockOneTimeTokenRepo{
		getOneTimeTokenByHashAndTypeFunc: func(ctx context.Context, tokenHash string, tokenType models.TokenType) (*models.OneTimeToken, error) {
			if tokenHash != hash {
				t.Fatalf("expected hash %s, got %s", hash, tokenHash)
			}

			return &models.OneTimeToken{
				ID:        tokenID,
				UserID:    userID,
				TokenHash: hash,
				Type:      models.TokenTypeEmailVerification,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		markOneTimeTokenUsedFunc: func(ctx context.Context, id uuid.UUID) error {
			if id != tokenID {
				t.Fatalf("expected token id %s, got %s", tokenID, id)
			}

			return nil
		},
	}

	userRepo := &mockUserRepo{
		getUserByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{
				ID:            userID,
				Email:         "test@example.com",
				EmailVerified: false,
			}, nil
		},
		updateUserFunc: func(ctx context.Context, user *models.User) error {
			if !user.EmailVerified {
				t.Fatal("expected email verified true")
			}

			return nil
		},
	}

	repo := &repository.Repo{
		UserRepository:   userRepo,
		OneTimeTokenRepo: oneTimeRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.VerifyEmail(context.Background(), models.VerifyEmailInput{
		Token: rawToken,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected success true")
	}

	if result.UserID != userID {
		t.Fatalf("expected user id %s, got %s", userID, result.UserID)
	}

	if !result.EmailVerified {
		t.Fatal("expected email verified true")
	}
}

func TestAuthService_RequestPasswordReset_UserNotFound_ReturnsSuccess(t *testing.T) {
	userRepo := &mockUserRepo{
		getUserByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return nil, sql.ErrNoRows
		},
	}

	repo := &repository.Repo{
		UserRepository: userRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.RequestPasswordReset(context.Background(), models.RequestPasswordResetInput{
		Email: "test@example.com",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected success true")
	}

	if result.ExpiresAtUnix != 0 {
		t.Fatalf("expected expires_at_unix 0, got %d", result.ExpiresAtUnix)
	}
}

func TestAuthService_ResetPassword_Success(t *testing.T) {
	userID := uuid.New()
	tokenID := uuid.New()
	rawToken := "reset-token"
	hash := hashToken(rawToken)

	oneTimeRepo := &mockOneTimeTokenRepo{
		getOneTimeTokenByHashAndTypeFunc: func(ctx context.Context, tokenHash string, tokenType models.TokenType) (*models.OneTimeToken, error) {
			if tokenHash != hash {
				t.Fatalf("expected hash %s, got %s", hash, tokenHash)
			}

			if tokenType != models.TokenTypePasswordReset {
				t.Fatalf("expected password reset token type, got %s", tokenType)
			}

			return &models.OneTimeToken{
				ID:        tokenID,
				UserID:    userID,
				TokenHash: hash,
				Type:      models.TokenTypePasswordReset,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		markOneTimeTokenUsedFunc: func(ctx context.Context, id uuid.UUID) error {
			if id != tokenID {
				t.Fatalf("expected token id %s, got %s", tokenID, id)
			}

			return nil
		},
	}

	userRepo := &mockUserRepo{
		getUserByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{
				ID:    userID,
				Email: "test@example.com",
			}, nil
		},
	}

	txRepo := &mockTXRepo{
		resetPasswordFunc: func(ctx context.Context, id uuid.UUID, passwordHash string) (int32, error) {
			if id != userID {
				t.Fatalf("expected user id %s, got %s", userID, id)
			}

			if passwordHash == "" {
				t.Fatal("expected password hash")
			}

			return 4, nil
		},
	}

	repo := &repository.Repo{
		UserRepository:   userRepo,
		OneTimeTokenRepo: oneTimeRepo,
		TXRepository:     txRepo,
	}

	svc := newTestService(repo, &mockMailService{}, t)

	result, err := svc.ResetPassword(context.Background(), models.ResetPasswordInput{
		Token:       rawToken,
		NewPassword: "new-password",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected success true")
	}

	if result.InvalidatedSessionsCount != 4 {
		t.Fatalf("expected invalidated sessions count 4, got %d", result.InvalidatedSessionsCount)
	}
}
