package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"department/models"
	"department/src/core/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type mockDepartmentRepo struct {
	createDepartmentFunc  func(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error)
	getDepartmentByIDFunc func(ctx context.Context, id uuid.UUID) (*models.Department, error)
	listDepartmentsFunc   func(ctx context.Context, in *models.ListDepartmentsInput) ([]*models.Department, int64, error)
	updateDepartmentFunc  func(ctx context.Context, in *models.UpdateDepartmentInput) (*models.Department, error)
	deleteDepartmentFunc  func(ctx context.Context, in *models.DeleteDepartmentInput) (*models.Department, error)
}

func (m *mockDepartmentRepo) CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error) {
	return m.createDepartmentFunc(ctx, in)
}

func (m *mockDepartmentRepo) GetDepartmentByID(ctx context.Context, id uuid.UUID) (*models.Department, error) {
	return m.getDepartmentByIDFunc(ctx, id)
}

func (m *mockDepartmentRepo) ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) ([]*models.Department, int64, error) {
	return m.listDepartmentsFunc(ctx, in)
}

func (m *mockDepartmentRepo) UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.Department, error) {
	return m.updateDepartmentFunc(ctx, in)
}

func (m *mockDepartmentRepo) DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.Department, error) {
	return m.deleteDepartmentFunc(ctx, in)
}

func newTestDepartmentService(repo repository.DepartmentRepository) *DepartmentServiceStruct {
	return NewDepartmentServiceStruct(&repository.Repository{DepartmentRepository: repo}, zap.NewNop())
}

func newDepartment(id uuid.UUID) *models.Department {
	return &models.Department{
		ID:          id,
		Name:        "Roads",
		Description: "Road maintenance",
		Status:      models.DepartmentStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func TestDepartmentService_CreateDepartment_Success(t *testing.T) {
	departmentID := uuid.New()
	svc := newTestDepartmentService(&mockDepartmentRepo{
		createDepartmentFunc: func(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error) {
			if in.Name != "Roads" {
				t.Fatalf("expected name Roads, got %s", in.Name)
			}
			return newDepartment(departmentID), nil
		},
	})

	result, err := svc.CreateDepartment(context.Background(), &models.CreateDepartmentInput{
		Name:       "Roads",
		ActorRoles: []string{"admin"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Department.ID != departmentID {
		t.Fatalf("expected department id %s, got %s", departmentID, result.Department.ID)
	}
}

func TestDepartmentService_CreateDepartment_InvalidInput(t *testing.T) {
	svc := newTestDepartmentService(&mockDepartmentRepo{})

	result, err := svc.CreateDepartment(context.Background(), &models.CreateDepartmentInput{
		Name:       "",
		ActorRoles: []string{"admin"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestDepartmentService_CreateDepartment_PermissionDenied(t *testing.T) {
	called := false
	svc := newTestDepartmentService(&mockDepartmentRepo{
		createDepartmentFunc: func(ctx context.Context, in *models.CreateDepartmentInput) (*models.Department, error) {
			called = true
			return nil, nil
		},
	})

	result, err := svc.CreateDepartment(context.Background(), &models.CreateDepartmentInput{
		Name:       "Roads",
		ActorRoles: []string{"operator"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied, got %v", err)
	}
	if called {
		t.Fatal("repo should not be called")
	}
}

func TestDepartmentService_GetDepartmentByID_Success(t *testing.T) {
	departmentID := uuid.New()
	svc := newTestDepartmentService(&mockDepartmentRepo{
		getDepartmentByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Department, error) {
			if id != departmentID {
				t.Fatalf("expected id %s, got %s", departmentID, id)
			}
			return newDepartment(departmentID), nil
		},
	})

	result, err := svc.GetDepartmentByID(context.Background(), &models.GetDepartmentByIDInput{ID: departmentID})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Department.ID != departmentID {
		t.Fatalf("expected department id %s, got %s", departmentID, result.Department.ID)
	}
}

func TestDepartmentService_GetDepartmentByID_NotFound(t *testing.T) {
	departmentID := uuid.New()
	svc := newTestDepartmentService(&mockDepartmentRepo{
		getDepartmentByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.Department, error) {
			return nil, models.ErrNotFound
		},
	})

	result, err := svc.GetDepartmentByID(context.Background(), &models.GetDepartmentByIDInput{ID: departmentID})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestDepartmentService_ListDepartments_Success(t *testing.T) {
	departmentID := uuid.New()
	svc := newTestDepartmentService(&mockDepartmentRepo{
		listDepartmentsFunc: func(ctx context.Context, in *models.ListDepartmentsInput) ([]*models.Department, int64, error) {
			if in.Limit != models.DefaultLimit {
				t.Fatalf("expected normalized limit %d, got %d", models.DefaultLimit, in.Limit)
			}
			return []*models.Department{newDepartment(departmentID)}, 1, nil
		},
	})

	result, err := svc.ListDepartments(context.Background(), &models.ListDepartmentsInput{})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Total != 1 || len(result.Departments) != 1 {
		t.Fatalf("expected one department, got total=%d len=%d", result.Total, len(result.Departments))
	}
}

func TestDepartmentService_UpdateDepartment_Success(t *testing.T) {
	departmentID := uuid.New()
	name := "Water"
	svc := newTestDepartmentService(&mockDepartmentRepo{
		updateDepartmentFunc: func(ctx context.Context, in *models.UpdateDepartmentInput) (*models.Department, error) {
			if in.ID != departmentID {
				t.Fatalf("expected id %s, got %s", departmentID, in.ID)
			}
			department := newDepartment(departmentID)
			department.Name = *in.Name
			return department, nil
		},
	})

	result, err := svc.UpdateDepartment(context.Background(), &models.UpdateDepartmentInput{
		ID:         departmentID,
		Name:       &name,
		ActorRoles: []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Department.Name != name {
		t.Fatalf("expected name %s, got %s", name, result.Department.Name)
	}
}

func TestDepartmentService_UpdateDepartment_RequiresChange(t *testing.T) {
	svc := newTestDepartmentService(&mockDepartmentRepo{})

	result, err := svc.UpdateDepartment(context.Background(), &models.UpdateDepartmentInput{
		ID:         uuid.New(),
		ActorRoles: []string{"admin"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestDepartmentService_DeleteDepartment_Success(t *testing.T) {
	departmentID := uuid.New()
	svc := newTestDepartmentService(&mockDepartmentRepo{
		deleteDepartmentFunc: func(ctx context.Context, in *models.DeleteDepartmentInput) (*models.Department, error) {
			if in.ID != departmentID {
				t.Fatalf("expected id %s, got %s", departmentID, in.ID)
			}
			department := newDepartment(departmentID)
			department.Status = models.DepartmentStatusArchived
			return department, nil
		},
	})

	result, err := svc.DeleteDepartment(context.Background(), &models.DeleteDepartmentInput{
		ID:         departmentID,
		ActorRoles: []string{"admin"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Department.Status != models.DepartmentStatusArchived {
		t.Fatalf("expected archived status, got %s", result.Department.Status)
	}
}

func TestDepartmentService_DeleteDepartment_PermissionDenied(t *testing.T) {
	svc := newTestDepartmentService(&mockDepartmentRepo{})

	result, err := svc.DeleteDepartment(context.Background(), &models.DeleteDepartmentInput{
		ID:         uuid.New(),
		ActorRoles: []string{"user"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied, got %v", err)
	}
}
