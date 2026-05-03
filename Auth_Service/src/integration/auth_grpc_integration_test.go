package integration

import (
	authv1 "auth/auth/v1"
	"auth/src/core/handler"
	"auth/src/core/service"
	"context"
	"net"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

type grpcTestApp struct {
	app        *testApp
	client     authv1.AuthServiceClient
	grpcServer *grpc.Server
	conn       *grpc.ClientConn
}

func newGRPCTestApp(t *testing.T) *grpcTestApp {
	t.Helper()

	app := newTestApp(t)

	listener := bufconn.Listen(bufSize)

	grpcServer := grpc.NewServer()

	authHandler := handler.NewAuthHandler(&service.Service{
		AuthService: app.auth,
	}, zap.NewNop())

	authv1.RegisterAuthServiceServer(grpcServer, authHandler)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	ctx := context.Background()

	conn, err := grpc.DialContext(
		ctx,
		"bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		grpcServer.Stop()
		app.cleanup()
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	client := authv1.NewAuthServiceClient(conn)

	return &grpcTestApp{
		app:        app,
		client:     client,
		grpcServer: grpcServer,
		conn:       conn,
	}
}

func (g *grpcTestApp) cleanup() {
	_ = g.conn.Close()
	g.grpcServer.Stop()
	g.app.cleanup()
}

func TestAuthGRPCIntegration_RegisterLoginRefreshLogout(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	ctx := context.Background()

	email := uniqueEmail()
	password := "Password123!"

	registerResp, err := grpcApp.client.Register(ctx, &authv1.RegisterRequest{
		Email:    email,
		Username: "grpc_user",
		Password: password,
	})
	if err != nil {
		t.Fatalf("grpc register failed: %v", err)
	}

	if registerResp.UserId == "" {
		t.Fatal("expected user id")
	}

	loginResp, err := grpcApp.client.Login(ctx, &authv1.LoginRequest{
		Email:     email,
		Password:  password,
		ClientId:  "web-client",
		Ip:        "127.0.0.1",
		UserAgent: "grpc-integration-test",
	})
	if err != nil {
		t.Fatalf("grpc login failed: %v", err)
	}

	if loginResp.AccessToken == "" {
		t.Fatal("expected access token")
	}

	if loginResp.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}

	if loginResp.SessionId == "" {
		t.Fatal("expected session id")
	}

	refreshResp, err := grpcApp.client.Refresh(ctx, &authv1.RefreshRequest{
		RefreshToken: loginResp.RefreshToken,
		ClientId:     "web-client",
		Ip:           "127.0.0.1",
		UserAgent:    "grpc-integration-test",
	})
	if err != nil {
		t.Fatalf("grpc refresh failed: %v", err)
	}

	if refreshResp.AccessToken == "" {
		t.Fatal("expected refreshed access token")
	}

	if refreshResp.RefreshToken == "" {
		t.Fatal("expected refreshed refresh token")
	}

	authInfoResp, err := grpcApp.client.GetUserAuthInfo(ctx, &authv1.GetUserAuthInfoRequest{
		UserId: registerResp.UserId,
	})
	if err != nil {
		t.Fatalf("grpc get user auth info failed: %v", err)
	}

	if authInfoResp.UserId != registerResp.UserId {
		t.Fatalf("expected user id %s, got %s", registerResp.UserId, authInfoResp.UserId)
	}

	if authInfoResp.Email != email {
		t.Fatalf("expected email %s, got %s", email, authInfoResp.Email)
	}

	_, err = grpcApp.client.Logout(ctx, &authv1.LogoutRequest{
		UserId:    registerResp.UserId,
		SessionId: loginResp.SessionId,
	})
	if err != nil {
		t.Fatalf("grpc logout failed: %v", err)
	}

	_, err = grpcApp.client.Refresh(ctx, &authv1.RefreshRequest{
		RefreshToken: refreshResp.RefreshToken,
		ClientId:     "web-client",
		Ip:           "127.0.0.1",
		UserAgent:    "grpc-integration-test",
	})
	if err == nil {
		t.Fatal("expected grpc refresh to fail after logout")
	}
}

func TestAuthGRPCIntegration_DuplicateRegisterFails(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	ctx := context.Background()

	email := uniqueEmail()

	_, err := grpcApp.client.Register(ctx, &authv1.RegisterRequest{
		Email:    email,
		Username: "first_grpc_user",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("first grpc register failed: %v", err)
	}

	_, err = grpcApp.client.Register(ctx, &authv1.RegisterRequest{
		Email:    email,
		Username: "second_grpc_user",
		Password: "Password123!",
	})
	if err == nil {
		t.Fatal("expected duplicate grpc register to fail")
	}
}

func TestAuthGRPCIntegration_GetJWKS(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	ctx := context.Background()

	resp, err := grpcApp.client.GetJWKS(ctx, &authv1.GetJWKSRequest{})
	if err != nil {
		t.Fatalf("grpc get jwks failed: %v", err)
	}

	if resp.JwksJson == "" {
		t.Fatal("expected jwks_json not empty")
	}
}
