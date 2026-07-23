package integration

import (
	"context"
	"net"
	"testing"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"profile/src/core/handler"
)

const bufSize = 1024 * 1024

type grpcTestApp struct {
	app        *testApp
	client     profilev1.ProfileServiceClient
	grpcServer *grpc.Server
	conn       *grpc.ClientConn
}

func newGRPCTestApp(t *testing.T) *grpcTestApp {
	t.Helper()

	app := newTestApp(t)
	listener := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()

	profileHandler := handler.NewProfileHandler(app.service, zap.NewNop())
	profilev1.RegisterProfileServiceServer(grpcServer, profileHandler)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
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

	return &grpcTestApp{
		app:        app,
		client:     profilev1.NewProfileServiceClient(conn),
		grpcServer: grpcServer,
		conn:       conn,
	}
}

func (g *grpcTestApp) cleanup() {
	_ = g.conn.Close()
	g.grpcServer.Stop()
	g.app.cleanup()
}

func TestProfileGRPCIntegration_UserWorkAndSkills(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	userID := uuid.New()
	departmentID := uuid.New()
	skillID := uuid.New()
	actorCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"x-actor-user-id", userID.String(),
		"x-actor-roles", "admin",
	))

	userResp, err := grpcApp.client.CreateUserProfile(actorCtx, &profilev1.CreateUserProfileRequest{
		UserId:                 userID.String(),
		FullName:               "Grpc User",
		PreferredContactMethod: profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_EMAIL,
	})
	if err != nil {
		t.Fatalf("grpc create user profile failed: %v", err)
	}
	if userResp.GetUserProfile().GetId() == "" {
		t.Fatal("expected user profile id")
	}

	workResp, err := grpcApp.client.CreateWorkProfile(actorCtx, &profilev1.CreateWorkProfileRequest{
		UserProfileId: userResp.GetUserProfile().GetId(),
		DepartmentId:  departmentID.String(),
		Position:      "Dispatcher",
	})
	if err != nil {
		t.Fatalf("grpc create work profile failed: %v", err)
	}
	if workResp.GetDetails().GetWorkProfile().GetId() == "" {
		t.Fatal("expected work profile id")
	}

	typeResp, err := grpcApp.client.CreateCertificationType(actorCtx, &profilev1.CreateCertificationTypeRequest{
		Code:         uniqueCode("grpc-cert"),
		Name:         "GRPC certificate",
		RequiresFile: false,
	})
	if err != nil {
		t.Fatalf("grpc create certification type failed: %v", err)
	}

	_, err = grpcApp.client.AddCertificationTypeSkill(actorCtx, &profilev1.AddCertificationTypeSkillRequest{
		CertificationTypeId: typeResp.GetCertificationType().GetId(),
		SkillId:             skillID.String(),
	})
	if err != nil {
		t.Fatalf("grpc add certification type skill failed: %v", err)
	}

	uploadResp, err := grpcApp.client.UploadWorkProfileCertification(actorCtx, &profilev1.UploadWorkProfileCertificationRequest{
		WorkProfileId:       workResp.GetDetails().GetWorkProfile().GetId(),
		CertificationTypeId: typeResp.GetCertificationType().GetId(),
	})
	if err != nil {
		t.Fatalf("grpc upload certification failed: %v", err)
	}

	verifyResp, err := grpcApp.client.VerifyWorkProfileCertification(actorCtx, &profilev1.VerifyWorkProfileCertificationRequest{
		Id: uploadResp.GetCertification().GetId(),
	})
	if err != nil {
		t.Fatalf("grpc verify certification failed: %v", err)
	}
	if len(verifyResp.GetSkillGrants()) != 1 || verifyResp.GetSkillGrants()[0].GetSkillId() != skillID.String() {
		t.Fatalf("unexpected skill grants: %+v", verifyResp.GetSkillGrants())
	}
}

func TestProfileGRPCIntegration_InvalidIDFails(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	_, err := grpcApp.client.GetUserProfileByID(context.Background(), &profilev1.GetUserProfileByIDRequest{Id: "bad-id"})
	if err == nil {
		t.Fatal("expected grpc get to fail")
	}
}
