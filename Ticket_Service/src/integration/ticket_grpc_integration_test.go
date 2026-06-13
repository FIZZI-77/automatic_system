package integration

import (
	"context"
	"net"
	"testing"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"ticket/src/core/handler"
)

const bufSize = 1024 * 1024

type grpcTestApp struct {
	app        *testApp
	client     ticketv1.TicketServiceClient
	grpcServer *grpc.Server
	conn       *grpc.ClientConn
}

func newGRPCTestApp(t *testing.T) *grpcTestApp {
	t.Helper()

	app := newTestApp(t)

	listener := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	ticketHandler := handler.NewTicketHandler(app.service, zap.NewNop())

	ticketv1.RegisterTicketServiceServer(grpcServer, ticketHandler)

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
		client:     ticketv1.NewTicketServiceClient(conn),
		grpcServer: grpcServer,
		conn:       conn,
	}
}

func (g *grpcTestApp) cleanup() {
	_ = g.conn.Close()
	g.grpcServer.Stop()
	g.app.cleanup()
}

func actorContext(userID uuid.UUID, roles ...string) context.Context {
	return metadata.AppendToOutgoingContext(
		context.Background(),
		"x-actor-user-id", userID.String(),
		"x-actor-roles", joinRoles(roles),
	)
}

func joinRoles(roles []string) string {
	if len(roles) == 0 {
		return ""
	}

	result := roles[0]
	for _, role := range roles[1:] {
		result += "," + role
	}

	return result
}

func TestTicketGRPCIntegration_TicketLifecycle(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	adminID := uuid.New()
	userID := uuid.New()
	departmentID := uuid.New()

	adminCtx := actorContext(adminID, "admin")
	userCtx := actorContext(userID)

	categoryResp, err := grpcApp.client.CreateCategory(adminCtx, &ticketv1.CreateCategoryRequest{
		Code:        uniqueCode("grpc-category"),
		Name:        "gRPC category",
		Description: "Created by gRPC integration test",
	})
	if err != nil {
		t.Fatalf("grpc create category failed: %v", err)
	}

	ticketResp, err := grpcApp.client.CreateTicket(userCtx, &ticketv1.CreateTicketRequest{
		DepartmentId: departmentID.String(),
		CategoryId:   categoryResp.GetCategory().GetId(),
		UserId:       userID.String(),
		Title:        "gRPC ticket",
		Description:  "Created by gRPC integration test",
		Priority:     ticketv1.TicketPriority_TICKET_PRIORITY_HIGH,
		Address:      "gRPC street 1",
		Latitude:     float64Ptr(55.751244),
		Longitude:    float64Ptr(37.618423),
	})
	if err != nil {
		t.Fatalf("grpc create ticket failed: %v", err)
	}

	if ticketResp.GetTicket().GetStatus() != ticketv1.TicketStatus_TICKET_STATUS_NEW {
		t.Fatalf("expected NEW status, got %s", ticketResp.GetTicket().GetStatus())
	}

	getResp, err := grpcApp.client.GetTicket(userCtx, &ticketv1.GetTicketRequest{
		TicketId: ticketResp.GetTicket().GetId(),
	})
	if err != nil {
		t.Fatalf("grpc get own ticket failed: %v", err)
	}

	if getResp.GetTicket().GetId() != ticketResp.GetTicket().GetId() {
		t.Fatalf("expected ticket id %s, got %s", ticketResp.GetTicket().GetId(), getResp.GetTicket().GetId())
	}

	brigadeID := uuid.New()
	assignResp, err := grpcApp.client.AssignBrigade(adminCtx, &ticketv1.AssignBrigadeRequest{
		TicketId:   ticketResp.GetTicket().GetId(),
		BrigadeId:  brigadeID.String(),
		AssignedBy: adminID.String(),
		Comment:    "Assigned by gRPC integration test",
	})
	if err != nil {
		t.Fatalf("grpc assign brigade failed: %v", err)
	}

	if assignResp.GetTicket().GetBrigadeId() != brigadeID.String() {
		t.Fatalf("expected brigade id %s, got %s", brigadeID, assignResp.GetTicket().GetBrigadeId())
	}

	statusResp, err := grpcApp.client.ChangeTicketStatus(adminCtx, &ticketv1.ChangeTicketStatusRequest{
		TicketId:  ticketResp.GetTicket().GetId(),
		NewStatus: ticketv1.TicketStatus_TICKET_STATUS_IN_PROGRESS,
		ChangedBy: adminID.String(),
		Comment:   "Work started by gRPC integration test",
	})
	if err != nil {
		t.Fatalf("grpc change status failed: %v", err)
	}

	if statusResp.GetTicket().GetStatus() != ticketv1.TicketStatus_TICKET_STATUS_IN_PROGRESS {
		t.Fatalf("expected IN_PROGRESS status, got %s", statusResp.GetTicket().GetStatus())
	}

	completeResp, err := grpcApp.client.CompleteTicket(adminCtx, &ticketv1.CompleteTicketRequest{
		TicketId:    ticketResp.GetTicket().GetId(),
		CompletedBy: adminID.String(),
		Comment:     "Completed by gRPC integration test",
	})
	if err != nil {
		t.Fatalf("grpc complete ticket failed: %v", err)
	}

	if completeResp.GetTicket().GetStatus() != ticketv1.TicketStatus_TICKET_STATUS_DONE {
		t.Fatalf("expected DONE status, got %s", completeResp.GetTicket().GetStatus())
	}

	historyResp, err := grpcApp.client.GetTicketStatusHistory(userCtx, &ticketv1.GetTicketStatusHistoryRequest{
		TicketId: ticketResp.GetTicket().GetId(),
		Limit:    20,
	})
	if err != nil {
		t.Fatalf("grpc get status history failed: %v", err)
	}

	if historyResp.GetTotal() < 3 {
		t.Fatalf("expected at least 3 history records, got %d", historyResp.GetTotal())
	}
}

func TestTicketGRPCIntegration_UpdateCategoryExplicitFalse(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	adminCtx := actorContext(uuid.New(), "dispatcher")

	createResp, err := grpcApp.client.CreateCategory(adminCtx, &ticketv1.CreateCategoryRequest{
		Code:        uniqueCode("grpc-inactive"),
		Name:        "gRPC inactive category",
		Description: "Created to verify optional is_active=false",
	})
	if err != nil {
		t.Fatalf("grpc create category failed: %v", err)
	}

	isActive := false
	updateResp, err := grpcApp.client.UpdateCategory(adminCtx, &ticketv1.UpdateCategoryRequest{
		CategoryId: createResp.GetCategory().GetId(),
		IsActive:   &isActive,
	})
	if err != nil {
		t.Fatalf("grpc update category failed: %v", err)
	}

	if updateResp.GetCategory().GetIsActive() {
		t.Fatal("expected category to be inactive after explicit is_active=false")
	}

	allResp, err := grpcApp.client.ListCategories(adminCtx, &ticketv1.ListCategoriesRequest{
		OnlyActive: boolPtr(false),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("grpc list all categories failed: %v", err)
	}

	foundInactive := false
	for _, category := range allResp.GetCategories() {
		if category.GetId() == createResp.GetCategory().GetId() {
			foundInactive = !category.GetIsActive()
		}
	}
	if !foundInactive {
		t.Fatal("expected inactive category to be present when only_active is false")
	}

	activeResp, err := grpcApp.client.ListCategories(adminCtx, &ticketv1.ListCategoriesRequest{
		OnlyActive: boolPtr(true),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("grpc list active categories failed: %v", err)
	}

	for _, category := range activeResp.GetCategories() {
		if category.GetId() == createResp.GetCategory().GetId() {
			t.Fatal("expected inactive category to be absent when only_active is true")
		}
	}
}

func float64Ptr(value float64) *float64 {
	return &value
}

func TestTicketGRPCIntegration_PermissionDeniedWithoutPrivilegedRole(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	userCtx := actorContext(uuid.New())

	_, err := grpcApp.client.CreateCategory(userCtx, &ticketv1.CreateCategoryRequest{
		Code: "grpc-denied",
		Name: "Denied category",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}
