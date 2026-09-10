package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"department/models"
	"department/src/core/service"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type mockDepartmentService struct {
	createDepartmentFunc  func(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error)
	getDepartmentByIDFunc func(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error)
	listDepartmentsFunc   func(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error)
	updateDepartmentFunc  func(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error)
	deleteDepartmentFunc  func(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error)
}

func (m *mockDepartmentService) CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error) {
	return m.createDepartmentFunc(ctx, in)
}
func (m *mockDepartmentService) GetDepartmentByID(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error) {
	return m.getDepartmentByIDFunc(ctx, in)
}
func (m *mockDepartmentService) ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error) {
	return m.listDepartmentsFunc(ctx, in)
}
func (m *mockDepartmentService) UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error) {
	return m.updateDepartmentFunc(ctx, in)
}
func (m *mockDepartmentService) DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error) {
	return m.deleteDepartmentFunc(ctx, in)
}

func newTestDepartmentHandler(mock *mockDepartmentService) *DepartmentHandler {
	return NewDepartmentHandler(&service.Service{DepartmentService: mock}, zap.NewNop())
}

func departmentHandlerContext(roles string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-roles", roles))
}

func assertDepartmentGRPCCode(t *testing.T, err error, expected codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}
	if st.Code() != expected {
		t.Fatalf("expected grpc code %v, got %v", expected, st.Code())
	}
}

func TestDepartmentHandler_CreateDepartment_Success(t *testing.T) {
	departmentID := uuid.New()
	mock := &mockDepartmentService{
		createDepartmentFunc: func(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error) {
			if in.Name != "Roads" {
				t.Fatalf("expected name Roads, got %s", in.Name)
			}
			if len(in.ActorRoles) != 2 || in.ActorRoles[0] != "admin" || in.ActorRoles[1] != "dispatcher" {
				t.Fatalf("unexpected actor roles: %#v", in.ActorRoles)
			}
			return &models.CreateDepartmentResult{Department: testDepartment(departmentID)}, nil
		},
	}
	h := newTestDepartmentHandler(mock)

	resp, err := h.CreateDepartment(departmentHandlerContext("admin, dispatcher"), &departmentv1.CreateDepartmentRequest{
		Name:        "Roads",
		Description: "Road maintenance",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetDepartment().GetId() != departmentID.String() {
		t.Fatalf("expected department id %s, got %s", departmentID, resp.GetDepartment().GetId())
	}
}

func TestDepartmentHandler_CreateDepartment_ValidationError(t *testing.T) {
	mock := &mockDepartmentService{
		createDepartmentFunc: func(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error) {
			return nil, models.ErrValidation
		},
	}
	h := newTestDepartmentHandler(mock)

	resp, err := h.CreateDepartment(context.Background(), &departmentv1.CreateDepartmentRequest{})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertDepartmentGRPCCode(t, err, codes.InvalidArgument)
}

func TestDepartmentHandler_GetDepartmentByID_Success(t *testing.T) {
	departmentID := uuid.New()
	mock := &mockDepartmentService{
		getDepartmentByIDFunc: func(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error) {
			if in.ID != departmentID {
				t.Fatalf("expected id %s, got %s", departmentID, in.ID)
			}
			return &models.GetDepartmentByIDResult{Department: testDepartment(departmentID)}, nil
		},
	}
	h := newTestDepartmentHandler(mock)

	resp, err := h.GetDepartmentByID(context.Background(), &departmentv1.GetDepartmentByIDRequest{Id: departmentID.String()})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetDepartment().GetName() != "Roads" {
		t.Fatalf("expected Roads, got %s", resp.GetDepartment().GetName())
	}
}

func TestDepartmentHandler_GetDepartmentByID_InvalidID(t *testing.T) {
	h := newTestDepartmentHandler(&mockDepartmentService{})

	resp, err := h.GetDepartmentByID(context.Background(), &departmentv1.GetDepartmentByIDRequest{Id: "bad-id"})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertDepartmentGRPCCode(t, err, codes.InvalidArgument)
}

func TestDepartmentHandler_ListDepartments_Success(t *testing.T) {
	departmentID := uuid.New()
	statusValue := departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE
	sortBy := departmentv1.DepartmentSortBy_DEPARTMENT_SORT_BY_NAME
	sortOrder := departmentv1.SortOrder_SORT_ORDER_ASC
	mock := &mockDepartmentService{
		listDepartmentsFunc: func(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error) {
			if in.Status == nil || *in.Status != models.DepartmentStatusActive {
				t.Fatalf("expected active status, got %v", in.Status)
			}
			if in.SortBy != models.DepartmentSortByName {
				t.Fatalf("expected sort by name, got %s", in.SortBy)
			}
			if in.SortOrder != models.SortOrderAsc {
				t.Fatalf("expected sort asc, got %s", in.SortOrder)
			}
			return &models.ListDepartmentsResult{Departments: []*models.Department{testDepartment(departmentID)}, Total: 1}, nil
		},
	}
	h := newTestDepartmentHandler(mock)

	resp, err := h.ListDepartments(context.Background(), &departmentv1.ListDepartmentsRequest{
		Status:    &statusValue,
		Limit:     10,
		Offset:    2,
		SortBy:    &sortBy,
		SortOrder: &sortOrder,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetTotal() != 1 || len(resp.GetDepartments()) != 1 {
		t.Fatalf("expected one department, got total=%d len=%d", resp.GetTotal(), len(resp.GetDepartments()))
	}
}

func TestDepartmentHandler_UpdateDepartment_Success(t *testing.T) {
	departmentID := uuid.New()
	name := "Water"
	statusValue := departmentv1.DepartmentStatus_DEPARTMENT_STATUS_INACTIVE
	mock := &mockDepartmentService{
		updateDepartmentFunc: func(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error) {
			if in.ID != departmentID {
				t.Fatalf("expected id %s, got %s", departmentID, in.ID)
			}
			if in.Name == nil || *in.Name != name {
				t.Fatalf("expected name %s, got %v", name, in.Name)
			}
			if in.Status == nil || *in.Status != models.DepartmentStatusInactive {
				t.Fatalf("expected inactive status, got %v", in.Status)
			}
			department := testDepartment(departmentID)
			department.Name = name
			department.Status = models.DepartmentStatusInactive
			return &models.UpdateDepartmentResult{Department: department}, nil
		},
	}
	h := newTestDepartmentHandler(mock)

	resp, err := h.UpdateDepartment(departmentHandlerContext("admin"), &departmentv1.UpdateDepartmentRequest{
		Id:     departmentID.String(),
		Name:   &name,
		Status: &statusValue,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetDepartment().GetStatus() != departmentv1.DepartmentStatus_DEPARTMENT_STATUS_INACTIVE {
		t.Fatalf("expected inactive status, got %s", resp.GetDepartment().GetStatus())
	}
}

func TestDepartmentHandler_DeleteDepartment_MapsNotFound(t *testing.T) {
	departmentID := uuid.New()
	mock := &mockDepartmentService{
		deleteDepartmentFunc: func(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error) {
			return nil, models.ErrNotFound
		},
	}
	h := newTestDepartmentHandler(mock)

	resp, err := h.DeleteDepartment(departmentHandlerContext("admin"), &departmentv1.DeleteDepartmentRequest{Id: departmentID.String()})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertDepartmentGRPCCode(t, err, codes.NotFound)
}

func TestDepartmentErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "validation", err: models.ErrValidation, code: codes.InvalidArgument},
		{name: "not found", err: models.ErrNotFound, code: codes.NotFound},
		{name: "already exists", err: models.ErrAlreadyExists, code: codes.AlreadyExists},
		{name: "permission", err: models.ErrPermissionDenied, code: codes.PermissionDenied},
		{name: "idempotency in progress", err: models.ErrIdempotencyInProgress, code: codes.Aborted},
		{name: "unknown", err: errors.New("boom"), code: codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := departmentErrorCode(tt.err); got != tt.code {
				t.Fatalf("expected %v, got %v", tt.code, got)
			}
		})
	}
}

func testDepartment(id uuid.UUID) *models.Department {
	return &models.Department{
		ID:          id,
		Name:        "Roads",
		Description: "Road maintenance",
		Status:      models.DepartmentStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}
