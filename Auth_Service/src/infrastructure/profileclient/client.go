package profileclient

import (
	"context"
	"fmt"
	"time"

	"auth/pkg"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const createProfileTimeout = 5 * time.Second

type Client struct {
	client profilev1.ProfileServiceClient
}

func (c *Client) UserProfileExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, createProfileTimeout)
	defer cancel()
	callCtx = profileContext(callCtx, ctx, userID)
	response, err := c.client.GetUserProfileByUserID(callCtx, &profilev1.GetUserProfileByUserIDRequest{UserId: userID.String()})
	if status.Code(err) == codes.NotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("profile GetUserProfileByUserID: %w", err)
	}
	return response.GetUserProfile() != nil && response.GetUserProfile().GetUserId() == userID.String(), nil
}

func New(client profilev1.ProfileServiceClient) *Client {
	return &Client{client: client}
}

func (c *Client) CreateUserProfile(ctx context.Context, userID uuid.UUID, fullName string) error {
	callCtx, cancel := context.WithTimeout(ctx, createProfileTimeout)
	defer cancel()

	callCtx = profileContext(callCtx, ctx, userID)

	_, err := c.client.CreateUserProfile(callCtx, &profilev1.CreateUserProfileRequest{
		UserId:   userID.String(),
		FullName: fullName,
	})
	if err != nil {
		return fmt.Errorf("profile CreateUserProfile: %w", err)
	}

	return nil
}

func profileContext(callCtx, source context.Context, userID uuid.UUID) context.Context {
	metadataPairs := []string{
		"x-actor-user-id", userID.String(),
		"x-actor-roles", "user",
	}
	if requestID, ok := pkg.RequestIDFromContext(source); ok {
		metadataPairs = append(metadataPairs, "x-request-id", requestID)
	}
	return metadata.NewOutgoingContext(callCtx, metadata.Pairs(metadataPairs...))
}
