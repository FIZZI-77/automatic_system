package handlers

import (
	"context"
	"gateway/models"
	"net/http"
	"time"

	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"github.com/gin-gonic/gin"
)

type FileHandler struct{ client filev1.FileServiceClient }

func NewFileHandler(client filev1.FileServiceClient) *FileHandler {
	return &FileHandler{client: client}
}

func (h *FileHandler) CreateUpload(c *gin.Context) {
	var req models.CreateFileUploadRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	res, err := h.client.CreateUpload(ctx, &filev1.CreateUploadRequest{OwnerUserId: c.GetString("user_id"), Name: req.Name, ContentType: req.ContentType, Size: req.Size, Checksum: req.Checksum})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"file": fromProtoFile(res.GetFile()), "upload_url": res.GetUploadUrl(), "expires_at": protoTime(res.GetExpiresAt())})
}

func (h *FileHandler) ConfirmUpload(c *gin.Context) {
	var req models.FileIDRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	res, err := h.client.ConfirmUpload(ctx, &filev1.ConfirmUploadRequest{FileId: req.FileID, ActorUserId: c.GetString("user_id"), ActorRoles: actorRoles(c)})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"file": fromProtoFile(res.GetFile())})
}

func (h *FileHandler) LinkFile(c *gin.Context) {
	var req models.LinkFileRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	res, err := h.client.LinkFile(ctx, &filev1.LinkFileRequest{FileId: req.FileID, ResourceType: req.ResourceType, ResourceId: req.ResourceID, ActorUserId: c.GetString("user_id"), ActorRoles: actorRoles(c)})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"file": fromProtoFile(res.GetFile())})
}

func (h *FileHandler) GetDownloadURL(c *gin.Context) {
	var req models.FileIDRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	res, err := h.client.GetDownloadURL(ctx, &filev1.GetDownloadURLRequest{FileId: req.FileID, ActorUserId: c.GetString("user_id"), ActorRoles: actorRoles(c)})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"file": fromProtoFile(res.GetFile()), "download_url": res.GetDownloadUrl(), "expires_at": protoTime(res.GetExpiresAt())})
}

func (h *FileHandler) ListResourceFiles(c *gin.Context) {
	var req models.ListResourceFilesRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	res, err := h.client.ListResourceFiles(ctx, &filev1.ListResourceFilesRequest{ResourceType: req.ResourceType, ResourceId: req.ResourceID, ActorUserId: c.GetString("user_id"), ActorRoles: actorRoles(c)})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	files := make([]*models.File, 0, len(res.GetFiles()))
	for _, file := range res.GetFiles() {
		files = append(files, fromProtoFile(file))
	}
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func (h *FileHandler) DeleteFile(c *gin.Context) {
	var req models.FileIDRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	_, err := h.client.DeleteFile(ctx, &filev1.DeleteFileRequest{FileId: req.FileID, ActorUserId: c.GetString("user_id"), ActorRoles: actorRoles(c)})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func actorRoles(c *gin.Context) []string {
	roles, _ := c.Get("roles")
	result, _ := roles.([]string)
	return result
}
func protoTime(value interface {
	AsTime() time.Time
	IsValid() bool
}) *time.Time {
	if value == nil || !value.IsValid() {
		return nil
	}
	parsed := value.AsTime()
	return &parsed
}
func fromProtoFile(file *filev1.File) *models.File {
	if file == nil {
		return nil
	}
	return &models.File{ID: file.GetId(), OwnerUserID: file.GetOwnerUserId(), ResourceType: file.ResourceType, ResourceID: file.ResourceId, Name: file.GetName(), ContentType: file.GetContentType(), Size: file.GetSize(), Checksum: file.GetChecksum(), Status: file.GetStatus().String(), CreatedAt: protoTime(file.GetCreatedAt()), UpdatedAt: protoTime(file.GetUpdatedAt())}
}
