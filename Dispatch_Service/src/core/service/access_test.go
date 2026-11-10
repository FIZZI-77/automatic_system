package service

import (
	"context"
	"errors"
	"testing"

	"dispatch/models"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

func TestOperationAccessRejectsOtherAndUnknownDepartments(t *testing.T) {
	department, other := uuid.New(), uuid.New()
	for _, test := range []struct {
		name       string
		department *uuid.UUID
		role       string
		allowed    bool
	}{
		{"own", &department, "dispatcher", true},
		{"foreign", &other, "dispatcher", false},
		{"legacy unknown", nil, "dispatcher", false},
		{"admin", &other, "admin", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-roles", test.role, "x-actor-department-id", department.String()))
			err := authorizeOperation(ctx, &models.Operation{DepartmentID: test.department})
			if test.allowed && err != nil || !test.allowed && !errors.Is(err, models.ErrForbidden) {
				t.Fatalf("access=%v, allowed=%v", err, test.allowed)
			}
		})
	}
	if _, err := actorDepartment(context.Background()); !errors.Is(err, models.ErrForbidden) {
		t.Fatalf("missing actor=%v", err)
	}
}
