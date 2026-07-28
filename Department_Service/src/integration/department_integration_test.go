package integration

import (
	"context"
	"testing"

	"department/models"
)

func TestDepartmentServiceIntegration_CreateListUpdateDelete(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()
	name := uniqueDepartmentName()

	createResult, err := app.department.CreateDepartment(ctx, &models.CreateDepartmentInput{
		Name:        name,
		Description: "integration department",
		ActorRoles:  []string{"admin"},
	})
	if err != nil {
		t.Fatalf("create department failed: %v", err)
	}
	if createResult.Department.ID.String() == "" {
		t.Fatal("expected department id")
	}

	getResult, err := app.department.GetDepartmentByID(ctx, &models.GetDepartmentByIDInput{ID: createResult.Department.ID})
	if err != nil {
		t.Fatalf("get department failed: %v", err)
	}
	if getResult.Department.Name != name {
		t.Fatalf("expected name %s, got %s", name, getResult.Department.Name)
	}

	listResult, err := app.department.ListDepartments(ctx, &models.ListDepartmentsInput{})
	if err != nil {
		t.Fatalf("list departments failed: %v", err)
	}
	if listResult.Total != 1 {
		t.Fatalf("expected total 1, got %d", listResult.Total)
	}

	newName := uniqueDepartmentName()
	updateResult, err := app.department.UpdateDepartment(ctx, &models.UpdateDepartmentInput{
		ID:         createResult.Department.ID,
		Name:       &newName,
		ActorRoles: []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("update department failed: %v", err)
	}
	if updateResult.Department.Name != newName {
		t.Fatalf("expected updated name %s, got %s", newName, updateResult.Department.Name)
	}

	deleteResult, err := app.department.DeleteDepartment(ctx, &models.DeleteDepartmentInput{
		ID:         createResult.Department.ID,
		ActorRoles: []string{"admin"},
	})
	if err != nil {
		t.Fatalf("delete department failed: %v", err)
	}
	if deleteResult.Department.Status != models.DepartmentStatusArchived {
		t.Fatalf("expected archived status, got %s", deleteResult.Department.Status)
	}
}

func TestDepartmentServiceIntegration_DuplicateNameFails(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()
	name := uniqueDepartmentName()

	_, err := app.department.CreateDepartment(ctx, &models.CreateDepartmentInput{Name: name, ActorRoles: []string{"admin"}})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = app.department.CreateDepartment(ctx, &models.CreateDepartmentInput{Name: name, ActorRoles: []string{"admin"}})
	if err == nil {
		t.Fatal("expected duplicate create to fail")
	}
}

func TestDepartmentServiceIntegration_PermissionDenied(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	_, err := app.department.CreateDepartment(context.Background(), &models.CreateDepartmentInput{
		Name:       uniqueDepartmentName(),
		ActorRoles: []string{"user"},
	})
	if err == nil {
		t.Fatal("expected permission denied")
	}
}
