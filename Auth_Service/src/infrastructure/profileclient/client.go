package profileclient

import (
	"context"
	"fmt"
	"time"

	"auth/pkg"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

const createProfileTimeout = 5 * time.Second

type Client struct {
	client profilev1.ProfileServiceClient
}

func New(client profilev1.ProfileServiceClient) *Client {
	return &Client{client: client}
}

func (c *Client) CreateUserProfile(ctx context.Context, userID uuid.UUID, fullName string) error {
	callCtx, cancel := context.WithTimeout(ctx, createProfileTimeout)
	defer cancel()

	metadataPairs := []string{
		"x-actor-user-id", userID.String(),
		"x-actor-roles", "user",
	}
	if requestID, ok := pkg.RequestIDFromContext(ctx); ok {
		metadataPairs = append(metadataPairs, "x-request-id", requestID)
	}
	callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs(metadataPairs...))

	_, err := c.client.CreateUserProfile(callCtx, &profilev1.CreateUserProfileRequest{
		UserId:   userID.String(),
		FullName: fullName,
	})
	if err != nil {
		return fmt.Errorf("profile CreateUserProfile: %w", err)
	}

	return nil
}
