package fileclient

import (
	"context"
	"testing"

	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type linkStub struct {
	filev1.FileServiceClient
	request *filev1.LinkFileRequest
	token   string
}

func (s *linkStub) LinkFile(ctx context.Context, request *filev1.LinkFileRequest, _ ...grpc.CallOption) (*filev1.LinkFileResponse, error) {
	s.request = request
	md, _ := metadata.FromOutgoingContext(ctx)
	values := md.Get("x-report-link-token")
	if len(values) == 1 {
		s.token = values[0]
	}
	return &filev1.LinkFileResponse{}, nil
}

func TestReportLinkCarriesPrivateCapabilityAndOriginalOwner(t *testing.T) {
	api := &linkStub{}
	client := New(api, "http://minio:9000", "private-token")
	file, resource, owner := uuid.New(), uuid.New(), uuid.New()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-report-link-token", "stale", "x-request-id", "correlation"))
	if err := client.LinkExisting(ctx, file, resource, owner, []string{"worker"}); err != nil {
		t.Fatal(err)
	}
	if api.token != "private-token" || api.request.GetActorUserId() != owner.String() || api.request.GetResourceId() != resource.String() || api.request.GetResourceType() != "work_report" {
		t.Fatalf("report link capability/owner/resource was lost: request=%+v", api.request)
	}
}
