package integration

import (
	"context"
	"testing"

	"brigade/src/core/handler"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

type grpcTestApp struct {
	app        *testApp
	client     brigadev1.BrigadeServiceClient
	grpcServer *grpc.Server
	conn       *grpc.ClientConn
}

func newGRPCTestApp(t *testing.T) *grpcTestApp {
	t.Helper()

	app := newTestApp(t)
	listener := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()

	brigadeHandler := handler.NewBrigadeHandler(app.service, zap.NewNop())
	brigadev1.RegisterBrigadeServiceServer(grpcServer, brigadeHandler)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(grpcDialer(listener)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		grpcServer.Stop()
		app.cleanup()
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	return &grpcTestApp{
		app:        app,
		client:     brigadev1.NewBrigadeServiceClient(conn),
		grpcServer: grpcServer,
		conn:       conn,
	}
}

func (g *grpcTestApp) cleanup() {
	_ = g.conn.Close()
	g.grpcServer.Stop()
	g.app.cleanup()
}

func TestBrigadeGRPCIntegration_CreateListAndMember(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	departmentID := uuid.New()
	actorID := uuid.New()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"x-actor-user-id", actorID.String(),
		"x-actor-department-id", departmentID.String(),
		"x-actor-roles", "dispatcher",
	))

	createResp, err := grpcApp.client.CreateBrigade(ctx, &brigadev1.CreateBrigadeRequest{
		DepartmentId: departmentID.String(),
		Name:         uniqueName("grpc-brigade"),
	})
	if err != nil {
		t.Fatalf("grpc create brigade failed: %v", err)
	}
	if createResp.GetBrigade().GetId() == "" {
		t.Fatal("expected brigade id")
	}

	departmentRaw := departmentID.String()
	listResp, err := grpcApp.client.ListBrigades(ctx, &brigadev1.ListBrigadesRequest{
		DepartmentId: &departmentRaw,
	})
	if err != nil {
		t.Fatalf("grpc list brigades failed: %v", err)
	}
	if listResp.GetTotal() != 1 {
		t.Fatalf("expected total 1, got %d", listResp.GetTotal())
	}

	memberResp, err := grpcApp.client.AddBrigadeMember(ctx, &brigadev1.AddBrigadeMemberRequest{
		BrigadeId: createResp.GetBrigade().GetId(),
		UserId:    uuid.NewString(),
		Role:      brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_LEAD,
	})
	if err != nil {
		t.Fatalf("grpc add member failed: %v", err)
	}
	if memberResp.GetMember().GetId() == "" {
		t.Fatal("expected member id")
	}
}

func TestBrigadeGRPCIntegration_InvalidIDFails(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	_, err := grpcApp.client.GetBrigadeByID(context.Background(), &brigadev1.GetBrigadeByIDRequest{Id: "bad-id"})
	if err == nil {
		t.Fatal("expected grpc get to fail")
	}
}
