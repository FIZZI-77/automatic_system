package service

import (
	"context"
	"strings"

	"dispatch/models"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

func actorDepartment(ctx context.Context) (*uuid.UUID, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	dispatcher := false
	for _, value := range md.Get("x-actor-roles") {
		for _, role := range strings.Split(value, ",") {
			if strings.TrimSpace(role) == "admin" {
				return nil, nil
			}
			if strings.TrimSpace(role) == "dispatcher" {
				dispatcher = true
			}
		}
	}
	values := md.Get("x-actor-department-id")
	if !dispatcher || len(values) != 1 {
		return nil, models.ErrForbidden
	}
	department, err := uuid.Parse(values[0])
	if err != nil || department == uuid.Nil {
		return nil, models.ErrForbidden
	}
	return &department, nil
}

func authorizeOperation(ctx context.Context, operation *models.Operation) error {
	department, err := actorDepartment(ctx)
	if err != nil {
		return err
	}
	if department != nil && (operation.DepartmentID == nil || *department != *operation.DepartmentID) {
		return models.ErrForbidden
	}
	return nil
}
