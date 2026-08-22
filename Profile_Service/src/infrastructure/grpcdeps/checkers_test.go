package grpcdeps

import (
	"context"
	"errors"
	"strings"
	"testing"

	authv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/auth/v1"
	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type authClientStub struct {
	authv1.AuthServiceClient
	get func(context.Context, *authv1.GetUserAuthInfoRequest, ...grpc.CallOption) (*authv1.GetUserAuthInfoResponse, error)
}

func (s authClientStub) GetUserAuthInfo(ctx context.Context, in *authv1.GetUserAuthInfoRequest, opts ...grpc.CallOption) (*authv1.GetUserAuthInfoResponse, error) {
	return s.get(ctx, in, opts...)
}

type departmentClientStub struct {
	departmentv1.DepartmentServiceClient
	get func(context.Context, *departmentv1.GetDepartmentByIDRequest, ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error)
}

func (s departmentClientStub) GetDepartmentByID(ctx context.Context, in *departmentv1.GetDepartmentByIDRequest, opts ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
	return s.get(ctx, in, opts...)
}

func TestUserChecker(t *testing.T) {
	userID := uuid.New()
	upstreamErr := errors.New("unavailable")
	tests := []struct {
		name     string
		response *authv1.GetUserAuthInfoResponse
		err      error
		wantErr  string
	}{
		{"active user", &authv1.GetUserAuthInfoResponse{UserId: userID.String(), IsActive: true}, nil, ""},
		{"inactive user", &authv1.GetUserAuthInfoResponse{UserId: userID.String(), IsActive: false}, nil, "inactive"},
		{"different user", &authv1.GetUserAuthInfoResponse{UserId: uuid.NewString(), IsActive: true}, nil, "does not exist"},
		{"nil response", nil, nil, "does not exist"},
		{"upstream error", nil, upstreamErr, "auth GetUserAuthInfo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewUserChecker(authClientStub{get: func(_ context.Context, in *authv1.GetUserAuthInfoRequest, _ ...grpc.CallOption) (*authv1.GetUserAuthInfoResponse, error) {
				if in.GetUserId() != userID.String() {
					t.Fatalf("user id = %q", in.GetUserId())
				}
				return tt.response, tt.err
			}})
			err := checker.EnsureUserExists(context.Background(), userID)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("error does not wrap upstream error: %v", err)
			}
		})
	}
}

func TestDepartmentChecker(t *testing.T) {
	departmentID := uuid.New()
	upstreamErr := errors.New("unavailable")
	tests := []struct {
		name     string
		response *departmentv1.GetDepartmentByIDResponse
		err      error
		wantErr  string
	}{
		{"active department", &departmentv1.GetDepartmentByIDResponse{Department: &departmentv1.Department{Id: departmentID.String(), Status: departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE}}, nil, ""},
		{"inactive department", &departmentv1.GetDepartmentByIDResponse{Department: &departmentv1.Department{Id: departmentID.String()}}, nil, "inactive"},
		{"different department", &departmentv1.GetDepartmentByIDResponse{Department: &departmentv1.Department{Id: uuid.NewString(), Status: departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE}}, nil, "does not exist"},
		{"missing department", &departmentv1.GetDepartmentByIDResponse{}, nil, "does not exist"},
		{"nil response", nil, nil, "does not exist"},
		{"upstream error", nil, upstreamErr, "department GetDepartmentByID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewDepartmentChecker(departmentClientStub{get: func(_ context.Context, in *departmentv1.GetDepartmentByIDRequest, _ ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
				if in.GetId() != departmentID.String() {
					t.Fatalf("department id = %q", in.GetId())
				}
				return tt.response, tt.err
			}})
			err := checker.EnsureDepartmentActive(context.Background(), departmentID)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("error does not wrap upstream error: %v", err)
			}
		})
	}
}
