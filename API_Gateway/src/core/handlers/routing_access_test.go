package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/metadata"
)

func TestRoutingContextPreservesResolvedActorExactlyOnce(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-actor-user-id", "actor", "x-actor-roles", "dispatcher", "x-actor-department-id", "department"))
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/routing/list", nil).WithContext(ctx)
	c.Set("user_id", "actor")
	c.Set("roles", []string{"dispatcher"})
	result := routingContext(c)
	defer c.MustGet("routing_cancel").(context.CancelFunc)()
	md, _ := metadata.FromOutgoingContext(result)
	if len(md.Get("x-actor-user-id")) != 1 || len(md.Get("x-actor-roles")) != 1 || md.Get("x-actor-department-id")[0] != "department" {
		t.Fatalf("resolved identity changed: %v", md)
	}
}
