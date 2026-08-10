package service

import (
	"context"
	"errors"
	"testing"

	"dispatch/models"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

func TestWorkflowRejectsInvalidInputsBeforeSideEffects(t *testing.T) {
	s := &Service{}
	tests := []struct {
		name string
		run  func() error
	}{
		{"preview", func() error { _, err := s.Preview(context.Background(), &models.RecommendInput{}); return err }},
		{"reserve", func() error { _, err := s.Reserve(context.Background(), &models.ReserveInput{}); return err }},
		{"confirm", func() error { _, err := s.Confirm(context.Background(), &models.ConfirmInput{}); return err }},
		{"auto", func() error { _, err := s.AutoDispatch(context.Background(), &models.AutoInput{}); return err }},
		{"cancel", func() error { _, err := s.Cancel(context.Background(), &models.CancelInput{}); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, models.ErrInvalidArgument) {
				t.Fatalf("expected invalid argument, got %v", err)
			}
		})
	}
}

func TestForwardMetadata(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-actor-user-id", uuid.NewString(), "x-actor-roles", "dispatcher"))
	outgoing, ok := metadata.FromOutgoingContext(forwardMetadata(ctx))
	if !ok || len(outgoing.Get("x-actor-user-id")) != 1 || outgoing.Get("x-actor-roles")[0] != "dispatcher" {
		t.Fatalf("metadata was not forwarded: %v", outgoing)
	}
}

func TestUUIDStrings(t *testing.T) {
	first, second := uuid.New(), uuid.New()
	result := uuidStrings([]uuid.UUID{first, second})
	if len(result) != 2 || result[0] != first.String() || result[1] != second.String() {
		t.Fatalf("unexpected UUID mapping: %v", result)
	}
}
