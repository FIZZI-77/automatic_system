package main

import (
	"context"
	"strings"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func profileDepartmentInterceptor(client profilev1.ProfileServiceClient) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		md = md.Copy()
		md.Delete("x-actor-department-id")

		if hasMetadataRole(md, "dispatcher") && !hasMetadataRole(md, "admin") {
			userIDs := md.Get("x-actor-user-id")
			if len(userIDs) == 0 || strings.TrimSpace(userIDs[0]) == "" {
				return nil, status.Error(codes.Unauthenticated, "dispatcher user id is missing")
			}
			result, err := client.ResolveWorkingDepartment(ctx, &profilev1.ResolveWorkingDepartmentRequest{
				UserId: strings.TrimSpace(userIDs[0]),
			})
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "resolve dispatcher department: %v", err)
			}
			if !result.GetCanOperate() || strings.TrimSpace(result.GetDepartmentId()) == "" {
				return nil, status.Error(codes.PermissionDenied, "dispatcher has no active working department")
			}
			md.Set("x-actor-department-id", result.GetDepartmentId())
		}

		return handler(metadata.NewIncomingContext(ctx, md), req)
	}
}

func hasMetadataRole(md metadata.MD, expected string) bool {
	for _, value := range md.Get("x-actor-roles") {
		for _, role := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(role), expected) {
				return true
			}
		}
	}
	return false
}
