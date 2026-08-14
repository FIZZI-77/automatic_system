package handlers

import (
	"net/http"

	"gateway/models"
	auditv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/audit/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuditHandler struct{ client auditv1.AuditServiceClient }

func NewAuditHandler(client auditv1.AuditServiceClient) *AuditHandler {
	return &AuditHandler{client: client}
}
func (h *AuditHandler) Get(c *gin.Context) {
	var request models.GetAuditEntryRequest
	if !bindJSON(c, &request) {
		return
	}
	response, err := h.client.GetAuditEntry(dispatchContext(c), &auditv1.GetAuditEntryRequest{Id: request.ID})
	dispatchResponse(c, http.StatusOK, err, response)
}
func (h *AuditHandler) List(c *gin.Context) {
	var request models.ListAuditEntriesRequest
	if !bindJSON(c, &request) {
		return
	}
	query := &auditv1.ListAuditEntriesRequest{ActorId: request.ActorID, Action: request.Action, EntityType: request.EntityType, EntityId: request.EntityID, RequestId: request.RequestID, TraceId: request.TraceID, Topic: request.Topic, Limit: request.Limit, Offset: request.Offset}
	if request.From != nil {
		query.From = timestamppb.New(*request.From)
	}
	if request.To != nil {
		query.To = timestamppb.New(*request.To)
	}
	response, err := h.client.ListAuditEntries(dispatchContext(c), query)
	dispatchResponse(c, http.StatusOK, err, response)
}
