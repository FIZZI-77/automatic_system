package handler

import (
	"context"
	"fmt"
	"testing"

	assetv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/asset/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"asset/models"
	"asset/src/core/service"
)

type writeService struct {
	service.AssetService
	allowed bool
	input   models.CreateInput
}

func (s *writeService) Create(_ context.Context, v models.CreateInput, p bool) (*models.Asset, error) {
	s.allowed = p
	s.input = v
	if !p {
		return nil, models.ErrForbidden
	}
	return &models.Asset{ID: uuid.New(), DepartmentID: v.DepartmentID}, nil
}
func TestAssetCreateAccess(t *testing.T) {
	t.Parallel()
	actor, department := uuid.New(), uuid.New()
	for _, tt := range []struct {
		role string
		want codes.Code
	}{{"user", codes.PermissionDenied}, {"admin", codes.OK}, {"dispatcher", codes.OK}} {
		t.Run(tt.role, func(t *testing.T) {
			t.Parallel()
			s := &writeService{}
			h := New(s)
			_, err := h.CreateAsset(context.Background(), &assetv1.CreateAssetRequest{DepartmentId: department.String(), ActorUserId: actor.String(), ActorRoles: []string{tt.role}})
			if status.Code(err) != tt.want || s.input.DepartmentID != department || s.input.ActorID != actor || s.allowed != (tt.want == codes.OK) {
				t.Fatalf("CreateAsset(%q) = %v, input=%+v, allowed=%v", tt.role, err, s.input, s.allowed)
			}
		})
	}
	if _, err := New(nil).CreateAsset(context.Background(), &assetv1.CreateAssetRequest{DepartmentId: "bad", ActorUserId: actor.String()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CreateAsset(invalid ID) = %v", err)
	}
}
func TestAssetErrorMapping(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		err  error
		want codes.Code
	}{{nil, codes.OK}, {fmt.Errorf("wrapped: %w", pgx.ErrNoRows), codes.NotFound}, {models.ErrForbidden, codes.PermissionDenied}, {context.Canceled, codes.InvalidArgument}} {
		if got := status.Code(mapErr(tt.err)); got != tt.want {
			t.Errorf("mapErr(%v) = %v; want %v", tt.err, got, tt.want)
		}
	}
}
