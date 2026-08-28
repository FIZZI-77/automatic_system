package fileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"report/models"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Client struct {
	api              filev1.FileServiceClient
	http             *http.Client
	internalEndpoint string
}

func New(api filev1.FileServiceClient, internal string) *Client {
	return &Client{api: api, http: &http.Client{Timeout: 30 * time.Second}, internalEndpoint: strings.TrimRight(internal, "/")}
}
func (c *Client) Upload(ctx context.Context, reportID, owner uuid.UUID, roles []string, a models.Artifact) (uuid.UUID, error) {
	return c.UploadForResource(ctx, "report", reportID, owner, roles, a)
}

func (c *Client) UploadForResource(ctx context.Context, resourceType string, resourceID, owner uuid.UUID, roles []string, a models.Artifact) (uuid.UUID, error) {
	sum := sha256.Sum256(a.Data)
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	created, e := c.api.CreateUpload(ctx, &filev1.CreateUploadRequest{OwnerUserId: owner.String(), Name: a.Name, ContentType: a.ContentType, Size: int64(len(a.Data)), Checksum: checksum})
	if e != nil {
		return uuid.Nil, e
	}
	original, e := url.Parse(created.UploadUrl)
	if e != nil {
		return uuid.Nil, e
	}
	target := c.internalURL(created.UploadUrl)
	req, e := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(a.Data))
	if e != nil {
		return uuid.Nil, e
	}
	req.Header.Set("Content-Type", a.ContentType)
	req.Header.Set("x-amz-checksum-sha256", checksum)
	req.Host = original.Host
	resp, e := c.http.Do(req)
	if e != nil {
		return uuid.Nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return uuid.Nil, fmt.Errorf("file upload returned %s", resp.Status)
	}
	id, e := uuid.Parse(created.File.Id)
	if e != nil {
		return uuid.Nil, e
	}
	if _, e = c.api.ConfirmUpload(ctx, &filev1.ConfirmUploadRequest{FileId: id.String(), ActorUserId: owner.String(), ActorRoles: roles}); e != nil {
		return uuid.Nil, e
	}
	_, e = c.api.LinkFile(ctx, &filev1.LinkFileRequest{FileId: id.String(), ResourceType: resourceType, ResourceId: resourceID.String(), ActorUserId: owner.String(), ActorRoles: roles})
	return id, e
}

func (c *Client) LinkExisting(ctx context.Context, fileID, resourceID, actor uuid.UUID, roles []string) error {
	_, err := c.api.LinkFile(ctx, &filev1.LinkFileRequest{FileId: fileID.String(), ResourceType: "work_report", ResourceId: resourceID.String(), ActorUserId: actor.String(), ActorRoles: roles})
	return err
}

func (c *Client) Delete(ctx context.Context, fileID, actor uuid.UUID, roles []string) error {
	_, err := c.api.DeleteFile(ctx, &filev1.DeleteFileRequest{
		FileId:      fileID.String(),
		ActorUserId: actor.String(),
		ActorRoles:  roles,
	})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

func (c *Client) DownloadImages(ctx context.Context, ids []uuid.UUID, actor uuid.UUID, roles []string) ([]models.EmbeddedImage, error) {
	result := make([]models.EmbeddedImage, 0, len(ids))
	for _, id := range ids {
		item, err := c.api.GetDownloadURL(ctx, &filev1.GetDownloadURLRequest{FileId: id.String(), ActorUserId: actor.String(), ActorRoles: roles})
		if err != nil {
			return nil, err
		}
		file := item.GetFile()
		if file == nil || !strings.HasPrefix(strings.ToLower(file.GetContentType()), "image/") {
			continue
		}
		target := c.internalURL(item.GetDownloadUrl())
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		if original, parseErr := url.Parse(item.GetDownloadUrl()); parseErr == nil {
			request.Host = original.Host
		}
		response, err := c.http.Do(request)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 20<<20))
		response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if response.StatusCode/100 != 2 {
			return nil, fmt.Errorf("file download returned %s", response.Status)
		}
		result = append(result, models.EmbeddedImage{Name: file.GetName(), ContentType: file.GetContentType(), Data: data})
	}
	return result, nil
}
func (c *Client) Download(ctx context.Context, id, actor uuid.UUID, roles []string) (string, time.Time, error) {
	x, e := c.api.GetDownloadURL(ctx, &filev1.GetDownloadURLRequest{FileId: id.String(), ActorUserId: actor.String(), ActorRoles: roles})
	if e != nil {
		return "", time.Time{}, e
	}
	return x.DownloadUrl, x.ExpiresAt.AsTime(), nil
}
func (c *Client) internalURL(raw string) string {
	if c.internalEndpoint == "" {
		return raw
	}
	u, e := url.Parse(raw)
	base, e2 := url.Parse(c.internalEndpoint)
	if e == nil && e2 == nil {
		u.Scheme = base.Scheme
		u.Host = base.Host
		return u.String()
	}
	return raw
}
