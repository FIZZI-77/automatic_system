package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHandleGRPCErrorFailedPreconditionReturnsConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)

	handleGRPCError(context, status.Error(codes.FailedPrecondition, "terminal state conflict"))

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	var payload map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["code"] != "INVALID_STATE" || payload["error"] != "Действие невозможно в текущем состоянии" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if payload["error"] == "terminal state conflict" {
		t.Fatal("internal gRPC message leaked to the client")
	}
}

func TestHandleGRPCErrorPermissionDeniedIsUserFriendly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	handleGRPCError(context, status.Error(codes.PermissionDenied, "failed ChangeTicketStatus: service: permission denied"))
	var payload map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if recorder.Code != http.StatusForbidden || payload["code"] != "PERMISSION_DENIED" || payload["error"] != "Недостаточно прав для выполнения действия" {
		t.Fatalf("unexpected response: status=%d payload=%#v", recorder.Code, payload)
	}
}
