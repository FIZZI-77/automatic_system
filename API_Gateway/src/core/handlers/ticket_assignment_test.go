package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/models"
	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type assignmentDispatchClient struct {
	dispatchv1.DispatchServiceClient
	reserve func(context.Context, *dispatchv1.ReserveBrigadeRequest) (*dispatchv1.ReserveBrigadeResponse, error)
	confirm func(context.Context, *dispatchv1.ConfirmDispatchRequest) (*dispatchv1.ConfirmDispatchResponse, error)
	list    func(context.Context, *dispatchv1.ListDispatchesRequest) (*dispatchv1.ListDispatchesResponse, error)
}

func (c *assignmentDispatchClient) ListDispatches(ctx context.Context, in *dispatchv1.ListDispatchesRequest, _ ...grpc.CallOption) (*dispatchv1.ListDispatchesResponse, error) {
	return c.list(ctx, in)
}

func (c *assignmentDispatchClient) ReserveBrigade(ctx context.Context, in *dispatchv1.ReserveBrigadeRequest, _ ...grpc.CallOption) (*dispatchv1.ReserveBrigadeResponse, error) {
	return c.reserve(ctx, in)
}

func (c *assignmentDispatchClient) ConfirmDispatch(ctx context.Context, in *dispatchv1.ConfirmDispatchRequest, _ ...grpc.CallOption) (*dispatchv1.ConfirmDispatchResponse, error) {
	return c.confirm(ctx, in)
}

type assignmentTicketClient struct {
	ticketv1.TicketServiceClient
	ticket *ticketv1.Ticket
	get    func() *ticketv1.Ticket
}

func (c *assignmentTicketClient) GetTicket(context.Context, *ticketv1.GetTicketRequest, ...grpc.CallOption) (*ticketv1.GetTicketResponse, error) {
	if c.get != nil {
		return &ticketv1.GetTicketResponse{Ticket: c.get()}, nil
	}
	return &ticketv1.GetTicketResponse{Ticket: c.ticket}, nil
}

func TestTicketAssignmentUsesDispatchAndAuthenticatedActor(t *testing.T) {
	actor, ticketID, brigadeID, operationID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	comment := "Проверенное ручное назначение"
	confirmed := false
	client := &assignmentDispatchClient{
		reserve: func(ctx context.Context, in *dispatchv1.ReserveBrigadeRequest) (*dispatchv1.ReserveBrigadeResponse, error) {
			md, _ := metadata.FromOutgoingContext(ctx)
			if in.GetTicketId() != ticketID || in.GetBrigadeId() != brigadeID || in.GetRequestedBy() != actor || strings.Join(md.Get("x-assignment-comment-bin"), "") != comment {
				t.Errorf("ReserveBrigade request = %v, metadata=%v, want validated IDs, authenticated actor and comment", in, md)
			}
			return &dispatchv1.ReserveBrigadeResponse{Operation: &dispatchv1.DispatchOperation{Id: operationID, Version: 2}}, nil
		},
		confirm: func(_ context.Context, in *dispatchv1.ConfirmDispatchRequest) (*dispatchv1.ConfirmDispatchResponse, error) {
			if in.GetId() != operationID || in.GetExpectedVersion() != 2 || in.GetConfirmedBy() != actor {
				t.Errorf("ConfirmDispatch request = %v, want reservation version and authenticated actor", in)
			}
			confirmed = true
			return &dispatchv1.ConfirmDispatchResponse{}, nil
		},
	}
	tickets := &assignmentTicketClient{get: func() *ticketv1.Ticket {
		if !confirmed {
			return &ticketv1.Ticket{Id: ticketID, Status: ticketv1.TicketStatus_TICKET_STATUS_NEW}
		}
		return &ticketv1.Ticket{Id: ticketID, BrigadeId: brigadeID, Status: ticketv1.TicketStatus_TICKET_STATUS_ASSIGNED}
	}}
	h := NewTicketHandler(tickets, nil, nil, client)
	body, err := json.Marshal(models.AssignBrigadeRequest{TicketID: ticketID, BrigadeID: brigadeID, AssignedBy: uuid.NewString(), Comment: comment})
	if err != nil {
		t.Fatal(err)
	}
	response := runAssignment(t, h, actor, string(body))
	if response.Code != http.StatusOK || !confirmed || !strings.Contains(response.Body.String(), brigadeID) {
		t.Fatalf("AssignBrigade response = (%d, %s), confirmed=%v, want assigned ticket", response.Code, response.Body.String(), confirmed)
	}
}

func TestTicketAssignmentRejectsIneligibleBrigadeBeforeConfirmation(t *testing.T) {
	client := &assignmentDispatchClient{reserve: func(context.Context, *dispatchv1.ReserveBrigadeRequest) (*dispatchv1.ReserveBrigadeResponse, error) {
		return nil, status.Error(codes.FailedPrecondition, "brigade belongs to another department")
	}}
	h := NewTicketHandler(&assignmentTicketClient{ticket: &ticketv1.Ticket{Status: ticketv1.TicketStatus_TICKET_STATUS_NEW}}, nil, nil, client)
	body := `{"ticket_id":"` + uuid.NewString() + `","brigade_id":"` + uuid.NewString() + `"}`
	response := runAssignment(t, h, uuid.NewString(), body)
	if response.Code != http.StatusConflict {
		t.Fatalf("AssignBrigade(ineligible brigade) status = %d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
}

func TestTicketAssignmentReplayDoesNotReserveAgain(t *testing.T) {
	ticketID, brigadeID := uuid.NewString(), uuid.NewString()
	tickets := &assignmentTicketClient{ticket: &ticketv1.Ticket{Id: ticketID, BrigadeId: brigadeID, Status: ticketv1.TicketStatus_TICKET_STATUS_ASSIGNED}}
	// Клиента Dispatch нет: успешно завершённый повтор не должен выполнять запись.
	h := NewTicketHandler(tickets, nil, nil, nil)
	response := runAssignment(t, h, uuid.NewString(), `{"ticket_id":"`+ticketID+`","brigade_id":"`+brigadeID+`"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("AssignBrigade(replay) status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
}

func TestTicketAssignmentResumesOnlyOwnMatchingReservation(t *testing.T) {
	actor, ticketID, brigadeID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, owner := range []string{actor, uuid.NewString()} {
		t.Run(owner, func(t *testing.T) {
			operation := &dispatchv1.DispatchOperation{Id: uuid.NewString(), RequestedBy: owner, BrigadeId: brigadeID, Version: 2}
			client := &assignmentDispatchClient{
				reserve: func(context.Context, *dispatchv1.ReserveBrigadeRequest) (*dispatchv1.ReserveBrigadeResponse, error) {
					return nil, status.Error(codes.Aborted, "ticket already reserved")
				},
				list: func(_ context.Context, in *dispatchv1.ListDispatchesRequest) (*dispatchv1.ListDispatchesResponse, error) {
					if in.GetTicketId() != ticketID || in.GetStatus() != dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED {
						t.Errorf("ListDispatches = %v, want reserved operation for %s", in, ticketID)
					}
					return &dispatchv1.ListDispatchesResponse{Operations: []*dispatchv1.DispatchOperation{operation}}, nil
				},
			}
			h := NewTicketHandler(nil, nil, nil, client)
			got, err := h.reserveTicketAssignment(t.Context(), &dispatchv1.ReserveBrigadeRequest{TicketId: ticketID, BrigadeId: brigadeID, RequestedBy: actor})
			if owner == actor {
				if err != nil || got.GetId() != operation.GetId() {
					t.Fatalf("reserveTicketAssignment(own retry) = (%v, %v), want existing reservation", got, err)
				}
			} else if status.Code(err) != codes.Aborted || got != nil {
				t.Fatalf("reserveTicketAssignment(foreign reservation) = (%v, %v), want conflict", got, err)
			}
		})
	}
}

func runAssignment(t *testing.T, h *TicketHandler, actor, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tickets/assign-brigade", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", actor)
	ctx.Set("roles", []string{"admin"})
	h.AssignBrigade(ctx)
	return response
}
