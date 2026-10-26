package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"gateway/models"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"google.golang.org/grpc"
)

type ticketIntegrationsClient struct {
	ticketv1.TicketServiceClient

	listFunc       func(context.Context, *ticketv1.ListIntegrationsRequest) (*ticketv1.ListIntegrationsResponse, error)
	setActiveFunc  func(context.Context, *ticketv1.SetIntegrationActiveRequest) (*ticketv1.SetIntegrationActiveResponse, error)
	rotateFunc     func(context.Context, *ticketv1.RotateIntegrationSecretRequest) (*ticketv1.RotateIntegrationSecretResponse, error)
}

func (c *ticketIntegrationsClient) ListIntegrations(
	ctx context.Context,
	in *ticketv1.ListIntegrationsRequest,
	_ ...grpc.CallOption,
) (*ticketv1.ListIntegrationsResponse, error) {
	return c.listFunc(ctx, in)
}

func (c *ticketIntegrationsClient) SetIntegrationActive(
	ctx context.Context,
	in *ticketv1.SetIntegrationActiveRequest,
	_ ...grpc.CallOption,
) (*ticketv1.SetIntegrationActiveResponse, error) {
	return c.setActiveFunc(ctx, in)
}

func (c *ticketIntegrationsClient) RotateIntegrationSecret(
	ctx context.Context,
	in *ticketv1.RotateIntegrationSecretRequest,
	_ ...grpc.CallOption,
) (*ticketv1.RotateIntegrationSecretResponse, error) {
	return c.rotateFunc(ctx, in)
}

func TestTicketHandlerListIntegrations(t *testing.T) {
	t.Parallel()

	client := &ticketIntegrationsClient{
		listFunc: func(_ context.Context, in *ticketv1.ListIntegrationsRequest) (*ticketv1.ListIntegrationsResponse, error) {
			if in.GetLimit() != 25 || in.GetOffset() != 5 {
				t.Errorf("ListIntegrations() pagination = %d/%d, want 25/5", in.GetLimit(), in.GetOffset())
			}
			return &ticketv1.ListIntegrationsResponse{
				Integrations: []*ticketv1.TicketIntegration{{Id: "integration-id", Name: "Portal", IsActive: true}},
				Total:        1,
			}, nil
		},
	}
	handler := NewTicketHandler(client, nil, nil)
	recorder, ctx := ticketRequestContext(t, "user-id", []string{"admin"}, `{"limit":25,"offset":5}`)

	handler.ListIntegrations(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ListIntegrations() status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response models.ListTicketIntegrationsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("ListIntegrations() decode error = %v, want nil", err)
	}
	if response.Total != 1 || len(response.Integrations) != 1 || response.Integrations[0].Name != "Portal" {
		t.Errorf("ListIntegrations() response = %+v, want one Portal integration", response)
	}
}

func TestTicketHandlerSetIntegrationActiveAcceptsFalse(t *testing.T) {
	t.Parallel()

	const integrationID = "10000000-0000-4000-8000-000000000001"
	client := &ticketIntegrationsClient{
		setActiveFunc: func(_ context.Context, in *ticketv1.SetIntegrationActiveRequest) (*ticketv1.SetIntegrationActiveResponse, error) {
			if in.GetIntegrationId() != integrationID || in.GetIsActive() {
				t.Errorf("SetIntegrationActive() input = %q/%t, want %q/false", in.GetIntegrationId(), in.GetIsActive(), integrationID)
			}
			return &ticketv1.SetIntegrationActiveResponse{Integration: &ticketv1.TicketIntegration{Id: integrationID}}, nil
		},
	}
	handler := NewTicketHandler(client, nil, nil)
	recorder, ctx := ticketRequestContext(t, "user-id", []string{"admin"}, `{"integration_id":"`+integrationID+`","is_active":false}`)

	handler.SetIntegrationActive(ctx)

	if recorder.Code != http.StatusOK {
		t.Errorf("SetIntegrationActive(false) status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestTicketHandlerRotateIntegrationSecret(t *testing.T) {
	t.Parallel()

	const integrationID = "10000000-0000-4000-8000-000000000002"
	client := &ticketIntegrationsClient{
		rotateFunc: func(_ context.Context, in *ticketv1.RotateIntegrationSecretRequest) (*ticketv1.RotateIntegrationSecretResponse, error) {
			if in.GetIntegrationId() != integrationID {
				t.Errorf("RotateIntegrationSecret() integration_id = %q, want %q", in.GetIntegrationId(), integrationID)
			}
			return &ticketv1.RotateIntegrationSecretResponse{
				Integration: &ticketv1.TicketIntegration{Id: integrationID, SecretPrefix: "tki_rotated"},
				Secret:      "tki_rotated-secret",
			}, nil
		},
	}
	handler := NewTicketHandler(client, nil, nil)
	recorder, ctx := ticketRequestContext(t, "user-id", []string{"admin"}, `{"integration_id":"`+integrationID+`"}`)

	handler.RotateIntegrationSecret(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("RotateIntegrationSecret() status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response models.RegisterTicketIntegrationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("RotateIntegrationSecret() decode error = %v, want nil", err)
	}
	if response.Secret != "tki_rotated-secret" {
		t.Errorf("RotateIntegrationSecret() secret = %q, want %q", response.Secret, "tki_rotated-secret")
	}
}
