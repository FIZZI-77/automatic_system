package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"gateway/models"

	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
)

type DispatchHandler struct {
	client  dispatchv1.DispatchServiceClient
	profile profilev1.ProfileServiceClient
}

func NewDispatchHandler(client dispatchv1.DispatchServiceClient, profile profilev1.ProfileServiceClient) *DispatchHandler {
	return &DispatchHandler{client: client, profile: profile}
}

func (h *DispatchHandler) Preview(c *gin.Context) {
	var in models.PreviewDispatchRequest

	if !bindJSON(c, &in) {
		return
	}

	ctx, ok := h.context(c)
	if !ok {
		return
	}
	out, err := h.client.PreviewDispatch(ctx, &dispatchv1.PreviewDispatchRequest{
		TicketId:         in.TicketID,
		RequiredSkillIds: in.RequiredSkillIDs,
		Limit:            in.Limit,
	})

	if err != nil {
		dispatchResponse(c, http.StatusOK, err, nil)
		return
	}

	// Generated protobuf JSON tags omit an empty repeated field, producing `{}`.
	// The HTTP contract should always expose the candidates collection.
	candidates := out.GetCandidates()

	if candidates == nil {
		candidates = make([]*dispatchv1.DispatchCandidate, 0)
	}

	dispatchResponse(c, http.StatusOK, nil, struct {
		Candidates []*dispatchv1.DispatchCandidate `json:"candidates"`
	}{Candidates: candidates})
}

func (h *DispatchHandler) Reserve(c *gin.Context) {
	var in models.ReserveBrigadeRequest

	if !bindJSON(c, &in) {
		return
	}

	req := &dispatchv1.ReserveBrigadeRequest{
		TicketId:              in.TicketID,
		BrigadeId:             in.BrigadeID,
		RequiredSkillIds:      in.RequiredSkillIDs,
		RequestedBy:           in.RequestedBy,
		ReservationTtlSeconds: in.ReservationTTLSeconds,
	}
	ctx, ok := h.context(c)
	if !ok {
		return
	}
	out, err := h.client.ReserveBrigade(ctx, req)
	dispatchResponse(c, http.StatusCreated, err, out)
}

func (h *DispatchHandler) Confirm(c *gin.Context) {
	var in models.ConfirmDispatchRequest

	if !bindJSON(c, &in) {
		return
	}

	ctx, ok := h.context(c)
	if !ok {
		return
	}
	out, err := h.client.ConfirmDispatch(ctx, &dispatchv1.ConfirmDispatchRequest{
		Id:              in.ID,
		ConfirmedBy:     in.ConfirmedBy,
		ExpectedVersion: in.ExpectedVersion,
	})
	dispatchResponse(c, http.StatusOK, err, out)
}

func (h *DispatchHandler) Auto(c *gin.Context) {
	var in models.AutoDispatchRequest

	if !bindJSON(c, &in) {
		return
	}

	ctx, ok := h.context(c)
	if !ok {
		return
	}
	out, err := h.client.AutoDispatch(ctx, &dispatchv1.AutoDispatchRequest{
		TicketId:         in.TicketID,
		RequiredSkillIds: in.RequiredSkillIDs,
		RequestedBy:      in.RequestedBy,
		CandidateLimit:   in.CandidateLimit,
	})
	dispatchResponse(c, http.StatusCreated, err, out)
}

func (h *DispatchHandler) Get(c *gin.Context) {
	var in models.GetDispatchRequest

	if !bindJSON(c, &in) {
		return
	}

	ctx, ok := h.context(c)
	if !ok {
		return
	}
	out, err := h.client.GetDispatch(ctx, &dispatchv1.GetDispatchRequest{Id: in.ID})
	dispatchResponse(c, http.StatusOK, err, out)
}

func (h *DispatchHandler) List(c *gin.Context) {
	var in models.ListDispatchesRequest

	if !bindJSON(c, &in) {
		return
	}

	req := &dispatchv1.ListDispatchesRequest{
		TicketId:  in.TicketID,
		BrigadeId: in.BrigadeID,
		Limit:     in.Limit,
		Offset:    in.Offset,
	}

	if in.Status != nil {
		value := dispatchStatus(*in.Status)
		req.Status = &value
	}

	ctx, ok := h.context(c)
	if !ok {
		return
	}
	out, err := h.client.ListDispatches(ctx, req)
	dispatchResponse(c, http.StatusOK, err, out)
}

func (h *DispatchHandler) Cancel(c *gin.Context) {
	var in models.CancelDispatchRequest

	if !bindJSON(c, &in) {
		return
	}

	ctx, ok := h.context(c)
	if !ok {
		return
	}
	out, err := h.client.CancelDispatch(ctx, &dispatchv1.CancelDispatchRequest{
		Id:              in.ID,
		CancelledBy:     in.CancelledBy,
		ExpectedVersion: in.ExpectedVersion,
		Reason:          in.Reason,
	})
	dispatchResponse(c, http.StatusOK, err, out)
}

func dispatchStatus(value string) dispatchv1.DispatchStatus {
	switch strings.ToUpper(value) {
	case "PENDING":
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_PENDING
	case "RESERVED":
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED
	case "CONFIRMING":
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_CONFIRMING
	case "ASSIGNED":
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_ASSIGNED
	case "FAILED":
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_FAILED
	case "CANCELLED":
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_CANCELLED
	case "EXPIRED":
		return dispatchv1.DispatchStatus_DISPATCH_STATUS_EXPIRED
	}
	return dispatchv1.DispatchStatus_DISPATCH_STATUS_UNSPECIFIED
}

func (h *DispatchHandler) context(c *gin.Context) (context.Context, bool) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	c.Set("dispatch_cancel", cancel)
	ctx = gatewayActorContext(ctx, c)
	resolved, err := h.profile.ResolveWorkingDepartment(ctx, &profilev1.ResolveWorkingDepartmentRequest{UserId: c.GetString("user_id")})
	if err != nil {
		dispatchResponse(c, http.StatusOK, err, nil)
		return ctx, false
	}
	if !resolved.GetCanOperate() || resolved.GetDepartmentId() == "" {
		cancel()
		writeAPIError(c, http.StatusForbidden, "PERMISSION_DENIED", "Рабочий профиль не разрешает операции")
		return ctx, false
	}
	return metadata.AppendToOutgoingContext(ctx, "x-actor-department-id", resolved.GetDepartmentId()), true
}

func dispatchResponse(c *gin.Context, code int, err error, response any) {

	if value, ok := c.Get("dispatch_cancel"); ok {

		if cancel, valid := value.(context.CancelFunc); valid {
			cancel()
		}

	}

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(code, response)
}
