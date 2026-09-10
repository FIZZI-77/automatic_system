package grpcdeps

import (
	"context"
	"errors"
	"fmt"

	"profile/models"

	authv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/auth/v1"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UserChecker struct {
	client authv1.AuthServiceClient
}

func NewUserChecker(client authv1.AuthServiceClient) *UserChecker {
	return &UserChecker{client: client}
}

func (c *UserChecker) EnsureUserExists(ctx context.Context, userID uuid.UUID) error {
	response, err := c.client.GetUserAuthInfo(ctx, &authv1.GetUserAuthInfoRequest{UserId: userID.String()})
	if err != nil {
		return fmt.Errorf("auth GetUserAuthInfo: %w", err)
	}
	if response.GetUserId() != userID.String() || !response.GetIsActive() {
		return fmt.Errorf("auth user %s does not exist or is inactive", userID)
	}
	return nil
}

type DepartmentChecker struct {
	client departmentv1.DepartmentServiceClient
}

func NewDepartmentChecker(client departmentv1.DepartmentServiceClient) *DepartmentChecker {
	return &DepartmentChecker{client: client}
}

func (c *DepartmentChecker) EnsureDepartmentActive(ctx context.Context, departmentID uuid.UUID) error {
	response, err := c.client.GetDepartmentByID(ctx, &departmentv1.GetDepartmentByIDRequest{Id: departmentID.String()})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return fmt.Errorf(
				"department GetDepartmentByID: %w",
				errors.Join(models.ErrNotFound, err),
			)
		}
		return fmt.Errorf("department GetDepartmentByID: %w", err)
	}
	if response.GetDepartment() == nil ||
		response.GetDepartment().GetId() != departmentID.String() ||
		response.GetDepartment().GetStatus() != departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE {
		return fmt.Errorf("department %s does not exist or is inactive: %w", departmentID, models.ErrNotFound)
	}
	return nil
}
