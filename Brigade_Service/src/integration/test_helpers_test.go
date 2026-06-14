package integration

import (
	"brigade/src/core/repository"
	"brigade/src/core/service"
	"context"
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type testApp struct {
	db      *sql.DB
	repo    *repository.Repo
	service *service.Service
	cleanup func()
}

type fakeDepartmentClient struct{}

func (f *fakeDepartmentClient) CreateDepartment(ctx context.Context, in *departmentv1.CreateDepartmentRequest, opts ...grpc.CallOption) (*departmentv1.CreateDepartmentResponse, error) {
	return nil, nil
}
func (f *fakeDepartmentClient) GetDepartmentByID(ctx context.Context, in *departmentv1.GetDepartmentByIDRequest, opts ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
	return &departmentv1.GetDepartmentByIDResponse{
		Department: &departmentv1.Department{
			Id:     in.GetId(),
			Name:   "Integration department",
			Status: departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE,
		},
	}, nil
}
func (f *fakeDepartmentClient) ListDepartments(ctx context.Context, in *departmentv1.ListDepartmentsRequest, opts ...grpc.CallOption) (*departmentv1.ListDepartmentsResponse, error) {
	return nil, nil
}
func (f *fakeDepartmentClient) UpdateDepartment(ctx context.Context, in *departmentv1.UpdateDepartmentRequest, opts ...grpc.CallOption) (*departmentv1.UpdateDepartmentResponse, error) {
	return nil, nil
}
func (f *fakeDepartmentClient) DeleteDepartment(ctx context.Context, in *departmentv1.DeleteDepartmentRequest, opts ...grpc.CallOption) (*departmentv1.DeleteDepartmentResponse, error) {
	return nil, nil
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgis/postgis:16-3.4-alpine",
		postgres.WithDatabase("brigade_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to open db: %v", err)
	}

	waitForDB(t, ctx, db)
	runGooseMigrations(t, db)

	repo := repository.NewRepo(db)
	brigadeService := service.NewService(repo, &fakeDepartmentClient{}, zap.NewNop())

	cleanup := func() {
		_ = db.Close()
		_ = container.Terminate(ctx)
	}

	return &testApp{
		db:      db,
		repo:    repo,
		service: brigadeService,
		cleanup: cleanup,
	}
}

func runGooseMigrations(t *testing.T, db *sql.DB) {
	t.Helper()

	migrationsDir := filepath.Clean("../../scheme")
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("failed to set goose dialect: %v", err)
	}
	if err := goose.Up(db, migrationsDir); err != nil {
		t.Fatalf("failed to apply goose migrations from %s: %v", migrationsDir, err)
	}
}

func waitForDB(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	var err error
	for i := 0; i < 15; i++ {
		err = db.PingContext(ctx)
		if err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("failed to ping db: %v", err)
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func grpcDialer(listener *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, s string) (net.Conn, error) {
		return listener.Dial()
	}
}
