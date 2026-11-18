package handlers

import (
	"context"

	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// reserveTicketAssignment возобновляет собственный резерв после потерянного ответа.
// Чужой резерв или другая бригада сохраняют исходный конфликт.
func (th *TicketHandler) reserveTicketAssignment(ctx context.Context, request *dispatchv1.ReserveBrigadeRequest) (*dispatchv1.DispatchOperation, error) {
	response, err := th.dispatchClient.ReserveBrigade(ctx, request)
	if err == nil {
		if response.GetOperation() == nil || response.GetOperation().GetId() == "" || response.GetOperation().GetVersion() <= 0 {
			return nil, status.Error(codes.Internal, "dispatch returned an invalid reservation")
		}
		return response.GetOperation(), nil
	}
	if status.Code(err) != codes.Aborted && status.Code(err) != codes.AlreadyExists {
		return nil, err
	}
	reserved := dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED
	ticketID := request.GetTicketId()
	existing, lookupErr := th.dispatchClient.ListDispatches(ctx, &dispatchv1.ListDispatchesRequest{TicketId: &ticketID, Status: &reserved, Limit: 1})
	if lookupErr != nil {
		return nil, err
	}
	for _, operation := range existing.GetOperations() {
		if operation.GetBrigadeId() == request.GetBrigadeId() && operation.GetRequestedBy() == request.GetRequestedBy() {
			return operation, nil
		}
	}
	return nil, err
}
