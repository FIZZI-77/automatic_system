package integration

import (
	"context"
	"net"
	"testing"

	"department/src/core/handler"
	"department/src/core/service"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

type grpcTestApp struct {
	app        *testApp
	client     departmentv1.DepartmentServiceClient
	grpcServer *grpc.Server
	conn       *grpc.ClientConn
}

func newGRPCTestApp(t *testing.T) *grpcTestApp {
	t.Helper()

	app := newTestApp(t)
	listener := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()

	departmentHandler := handler.NewDepartmentHandler(&service.Service{
		DepartmentService: app.department,
	}, zap.NewNop())
	departmentv1.RegisterDepartmentServiceServer(grpcServer, departmentHandler)

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
		client:     departmentv1.NewDepartmentServiceClient(conn),
		grpcServer: grpcServer,
		conn:       conn,
	}
}

func (g *grpcTestApp) cleanup() {
	_ = g.conn.Close()
	g.grpcServer.Stop()
	g.app.cleanup()
}

func TestDepartmentGRPCIntegration_CreateListUpdateDelete(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-actor-roles", "admin"))
	name := uniqueDepartmentName()

	createResp, err := grpcApp.client.CreateDepartment(ctx, &departmentv1.CreateDepartmentRequest{
		Name:        name,
		Description: "grpc department",
	})
	if err != nil {
		t.Fatalf("grpc create failed: %v", err)
	}
	if createResp.GetDepartment().GetId() == "" {
		t.Fatal("expected department id")
	}

	getResp, err := grpcApp.client.GetDepartmentByID(context.Background(), &departmentv1.GetDepartmentByIDRequest{
		Id: createResp.GetDepartment().GetId(),
	})
	if err != nil {
		t.Fatalf("grpc get failed: %v", err)
	}
	if getResp.GetDepartment().GetName() != name {
		t.Fatalf("expected name %s, got %s", name, getResp.GetDepartment().GetName())
	}

	listResp, err := grpcApp.client.ListDepartments(context.Background(), &departmentv1.ListDepartmentsRequest{})
	if err != nil {
		t.Fatalf("grpc list failed: %v", err)
	}
	if listResp.GetTotal() != 1 {
		t.Fatalf("expected total 1, got %d", listResp.GetTotal())
	}

	newName := uniqueDepartmentName()
	updateResp, err := grpcApp.client.UpdateDepartment(ctx, &departmentv1.UpdateDepartmentRequest{
		Id:   createResp.GetDepartment().GetId(),
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("grpc update failed: %v", err)
	}
	if updateResp.GetDepartment().GetName() != newName {
		t.Fatalf("expected updated name %s, got %s", newName, updateResp.GetDepartment().GetName())
	}

	deleteResp, err := grpcApp.client.DeleteDepartment(ctx, &departmentv1.DeleteDepartmentRequest{
		Id: createResp.GetDepartment().GetId(),
	})
	if err != nil {
		t.Fatalf("grpc delete failed: %v", err)
	}
	if deleteResp.GetDepartment().GetStatus() != departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ARCHIVED {
		t.Fatalf("expected archived status, got %s", deleteResp.GetDepartment().GetStatus())
	}
}

func TestDepartmentGRPCIntegration_InvalidIDFails(t *testing.T) {
	grpcApp := newGRPCTestApp(t)
	defer grpcApp.cleanup()

	_, err := grpcApp.client.GetDepartmentByID(context.Background(), &departmentv1.GetDepartmentByIDRequest{Id: "bad-id"})
	if err == nil {
		t.Fatal("expected grpc get to fail")
	}
}
