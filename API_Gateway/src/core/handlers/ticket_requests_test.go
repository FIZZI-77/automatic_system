package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/models"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

type ticketRequestsClient struct {
	ticketv1.TicketServiceClient

	createRequestFunc        func(context.Context, *ticketv1.CreateRequestRequest) (*ticketv1.CreateRequestResponse, error)
	attachRequestFunc        func(context.Context, *ticketv1.AttachRequestRequest) (*ticketv1.AttachRequestResponse, error)
	detachRequestFunc        func(context.Context, *ticketv1.DetachRequestRequest) (*ticketv1.DetachRequestResponse, error)
	listIncidentRequestsFunc func(context.Context, *ticketv1.ListIncidentRequestsRequest) (*ticketv1.ListIncidentRequestsResponse, error)
}

func (c *ticketRequestsClient) CreateRequest(
	ctx context.Context,
	in *ticketv1.CreateRequestRequest,
	_ ...grpc.CallOption,
) (*ticketv1.CreateRequestResponse, error) {
	return c.createRequestFunc(ctx, in)
}

func (c *ticketRequestsClient) AttachRequest(
	ctx context.Context,
	in *ticketv1.AttachRequestRequest,
	_ ...grpc.CallOption,
) (*ticketv1.AttachRequestResponse, error) {
	return c.attachRequestFunc(ctx, in)
}

func (c *ticketRequestsClient) DetachRequest(
	ctx context.Context,
	in *ticketv1.DetachRequestRequest,
	_ ...grpc.CallOption,
) (*ticketv1.DetachRequestResponse, error) {
	return c.detachRequestFunc(ctx, in)
}

func (c *ticketRequestsClient) ListIncidentRequests(
	ctx context.Context,
	in *ticketv1.ListIncidentRequestsRequest,
	_ ...grpc.CallOption,
) (*ticketv1.ListIncidentRequestsResponse, error) {
	return c.listIncidentRequestsFunc(ctx, in)
}

func TestTicketHandlerCreateRequest(t *testing.T) {
	t.Parallel()

	const (
		userID       = "10000000-0000-4000-8000-000000000001"
		departmentID = "20000000-0000-4000-8000-000000000001"
		categoryID   = "30000000-0000-4000-8000-000000000001"
		requestID    = "40000000-0000-4000-8000-000000000001"
		incidentID   = "50000000-0000-4000-8000-000000000001"
	)

	client := &ticketRequestsClient{
		createRequestFunc: func(_ context.Context, in *ticketv1.CreateRequestRequest) (*ticketv1.CreateRequestResponse, error) {
			if in.GetUserId() != userID || in.GetDepartmentId() != departmentID || in.GetCategoryId() != categoryID {
				t.Errorf(
					"CreateRequest() input = user %q, department %q, category %q, want %q, %q, %q",
					in.GetUserId(),
					in.GetDepartmentId(),
					in.GetCategoryId(),
					userID,
					departmentID,
					categoryID,
				)
			}

			return &ticketv1.CreateRequestResponse{
				Request:          requestProto(requestID, departmentID, incidentID, ticketv1.TicketStatus_TICKET_STATUS_NEW),
				Incident:         incidentProto(incidentID, departmentID, ticketv1.TicketStatus_TICKET_STATUS_NEW),
				DuplicateMatched: true,
			}, nil
		},
	}
	handler := NewTicketHandler(client, nil, nil)
	recorder, ctx := ticketRequestContext(
		t,
		userID,
		[]string{"user"},
		`{"department_id":"`+departmentID+`","category_id":"`+categoryID+`","title":"Light","description":"Broken light","priority":"HIGH","address":"Moscow","latitude":55.75,"longitude":37.61}`,
	)

	handler.CreateRequest(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("CreateRequest() status = %d, want %d; body = %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}

	var response models.CreateRequestResponse

	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("CreateRequest() decode response error = %v, want nil", err)
	}

	if response.Request == nil || response.Request.ID != requestID || response.Request.IncidentID != incidentID {
		t.Errorf("CreateRequest() request = %+v, want id %q and incident_id %q", response.Request, requestID, incidentID)
	}

	if response.Incident == nil || response.Incident.ID != incidentID || !response.DuplicateMatched {
		t.Errorf("CreateRequest() response = %+v, want incident %q and duplicate_matched true", response, incidentID)
	}
}

func TestTicketHandlerAttachAndDetachRequest(t *testing.T) {
	t.Parallel()

	const (
		userID       = "10000000-0000-4000-8000-000000000002"
		departmentID = "20000000-0000-4000-8000-000000000002"
		requestID    = "40000000-0000-4000-8000-000000000002"
		incidentID   = "50000000-0000-4000-8000-000000000002"
	)

	client := &ticketRequestsClient{
		attachRequestFunc: func(_ context.Context, in *ticketv1.AttachRequestRequest) (*ticketv1.AttachRequestResponse, error) {
			if in.GetIncidentId() != incidentID || in.GetRequestId() != requestID || in.GetReason() != "same incident" {
				t.Errorf("AttachRequest() input = %+v, want incident %q, request %q and reason %q", in, incidentID, requestID, "same incident")
			}

			return &ticketv1.AttachRequestResponse{
				Request: requestProto(requestID, departmentID, incidentID, ticketv1.TicketStatus_TICKET_STATUS_NEW),
			}, nil
		},
		detachRequestFunc: func(_ context.Context, in *ticketv1.DetachRequestRequest) (*ticketv1.DetachRequestResponse, error) {
			if in.GetRequestId() != requestID || in.GetReason() != "separate incident" {
				t.Errorf("DetachRequest() input = %+v, want request %q and reason %q", in, requestID, "separate incident")
			}

			return &ticketv1.DetachRequestResponse{
				Request: requestProto(requestID, departmentID, "", ticketv1.TicketStatus_TICKET_STATUS_NEW),
			}, nil
		},
	}
	handler := NewTicketHandler(client, nil, nil)

	attachRecorder, attachContext := ticketRequestContext(
		t,
		userID,
		[]string{"admin"},
		`{"incident_id":"`+incidentID+`","request_id":"`+requestID+`","reason":"same incident"}`,
	)
	handler.AttachRequest(attachContext)

	if attachRecorder.Code != http.StatusOK {
		t.Fatalf("AttachRequest() status = %d, want %d; body = %s", attachRecorder.Code, http.StatusOK, attachRecorder.Body.String())
	}

	var attached struct {
		Request *models.Ticket `json:"request"`
	}

	if err := json.Unmarshal(attachRecorder.Body.Bytes(), &attached); err != nil {
		t.Fatalf("AttachRequest() decode response error = %v, want nil", err)
	}

	if attached.Request == nil || attached.Request.IncidentID != incidentID {
		t.Errorf("AttachRequest() request = %+v, want incident_id %q", attached.Request, incidentID)
	}

	detachRecorder, detachContext := ticketRequestContext(
		t,
		userID,
		[]string{"admin"},
		`{"request_id":"`+requestID+`","reason":"separate incident"}`,
	)
	handler.DetachRequest(detachContext)

	if detachRecorder.Code != http.StatusOK {
		t.Fatalf("DetachRequest() status = %d, want %d; body = %s", detachRecorder.Code, http.StatusOK, detachRecorder.Body.String())
	}

	var detached struct {
		Request *models.Ticket `json:"request"`
	}

	if err := json.Unmarshal(detachRecorder.Body.Bytes(), &detached); err != nil {
		t.Fatalf("DetachRequest() decode response error = %v, want nil", err)
	}

	if detached.Request == nil || detached.Request.IncidentID != "" {
		t.Errorf("DetachRequest() request = %+v, want empty incident_id", detached.Request)
	}
}

func TestTicketHandlerListIncidentRequestsAggregatesAllPages(t *testing.T) {
	t.Parallel()

	const (
		userID     = "10000000-0000-4000-8000-000000000003"
		incidentID = "50000000-0000-4000-8000-000000000003"
	)

	requests := []*ticketv1.Ticket{
		requestProto("request-1", "department-a", incidentID, ticketv1.TicketStatus_TICKET_STATUS_DONE),
		requestProto("request-2", "department-b", incidentID, ticketv1.TicketStatus_TICKET_STATUS_IN_PROGRESS),
		requestProto("request-3", "department-b", incidentID, ticketv1.TicketStatus_TICKET_STATUS_DONE),
	}
	callCount := 0
	client := &ticketRequestsClient{
		listIncidentRequestsFunc: func(_ context.Context, in *ticketv1.ListIncidentRequestsRequest) (*ticketv1.ListIncidentRequestsResponse, error) {
			callCount++

			if callCount == 1 {
				if in.GetLimit() != 1 || in.GetOffset() != 1 {
					t.Errorf("ListIncidentRequests(first) page = limit %d offset %d, want 1 and 1", in.GetLimit(), in.GetOffset())
				}

				return &ticketv1.ListIncidentRequestsResponse{Requests: requests[1:2], Total: 3}, nil
			}

			if in.GetLimit() != 100 || in.GetOffset() != 0 {
				t.Errorf("ListIncidentRequests(aggregate) page = limit %d offset %d, want 100 and 0", in.GetLimit(), in.GetOffset())
			}

			return &ticketv1.ListIncidentRequestsResponse{Requests: requests, Total: 3}, nil
		},
	}
	handler := NewTicketHandler(client, nil, nil)
	recorder, ctx := ticketRequestContext(
		t,
		userID,
		[]string{"admin"},
		`{"incident_id":"`+incidentID+`","limit":1,"offset":1}`,
	)

	handler.ListIncidentRequests(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ListIncidentRequests() status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response models.ListIncidentRequestsResponse

	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("ListIncidentRequests() decode response error = %v, want nil", err)
	}

	if len(response.Requests) != 1 || response.Requests[0].ID != "request-2" {
		t.Errorf("ListIncidentRequests() page = %+v, want request-2 only", response.Requests)
	}

	if response.Total != 3 || response.Completed != 2 || response.DepartmentCount != 2 {
		t.Errorf(
			"ListIncidentRequests() metrics = total %d, completed %d, departments %d, want 3, 2, 2",
			response.Total,
			response.Completed,
			response.DepartmentCount,
		)
	}

	if !response.IsComposite || response.AllPartsCompleted {
		t.Errorf(
			"ListIncidentRequests() flags = composite %t, all completed %t, want true and false",
			response.IsComposite,
			response.AllPartsCompleted,
		)
	}

	if callCount != 2 {
		t.Errorf("ListIncidentRequests() call count = %d, want 2", callCount)
	}
}

func ticketRequestContext(
	t *testing.T,
	userID string,
	roles []string,
	body string,
) (*httptest.ResponseRecorder, *gin.Context) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tickets/requests", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", userID)
	ctx.Set("roles", roles)

	return recorder, ctx
}

func requestProto(
	id string,
	departmentID string,
	incidentID string,
	status ticketv1.TicketStatus,
) *ticketv1.Ticket {
	var incidentIDPointer *string

	if incidentID != "" {
		incidentIDPointer = &incidentID
	}

	return &ticketv1.Ticket{
		Id:           id,
		DepartmentId: departmentID,
		CategoryId:   "category",
		UserId:       "user",
		Title:        "request",
		Description:  "request description",
		Status:       status,
		Priority:     ticketv1.TicketPriority_TICKET_PRIORITY_HIGH,
		Address:      "Moscow",
		Latitude:     55.75,
		Longitude:    37.61,
		TicketType:   ticketv1.TicketType_TICKET_TYPE_REQUEST,
		IncidentId:   incidentIDPointer,
	}
}

func incidentProto(
	id string,
	departmentID string,
	status ticketv1.TicketStatus,
) *ticketv1.Ticket {
	ticket := requestProto(id, departmentID, "", status)
	ticket.TicketType = ticketv1.TicketType_TICKET_TYPE_INCIDENT

	return ticket
}
