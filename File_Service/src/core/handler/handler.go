package handler

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"file/models"
	"file/pkg"
	"file/src/core/service"
	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Handler struct {
	filev1.UnimplementedFileServiceServer
	service   *service.Service
	logger    *zap.Logger
	linkToken string
}

// New создаёт gRPC-обработчик файлов с сервисом и журналом запросов.
func New(fileService *service.Service, logger *zap.Logger, linkToken string) *Handler {
	return &Handler{service: fileService, logger: logger, linkToken: strings.TrimSpace(linkToken)}
}

// CreateUpload разбирает UUID владельца и передаёт метаданные файла сервису.
// Возвращает файл, URL загрузки и срок действия; неверный UUID даёт InvalidArgument.
func (h *Handler) CreateUpload(ctx context.Context, req *filev1.CreateUploadRequest) (*filev1.CreateUploadResponse, error) {
	logger := h.logger.With(pkg.RequestIDField(ctx), zap.String("method", "CreateUpload"))
	ownerID, err := parseUUID(req.GetOwnerUserId(), "owner_user_id")

	if err != nil {
		logger.Warn("invalid request", zap.Error(err))
		return nil, invalidArgument(err)
	}

	result, err := h.service.Create(ctx, models.CreateInput{
		OwnerUserID: ownerID,
		Name:        req.GetName(),
		ContentType: req.GetContentType(),
		Size:        req.GetSize(),
		Checksum:    req.GetChecksum(),
	})

	if err != nil {
		logger.Error("create upload failed", zap.Error(err))
		return nil, serviceError(err)
	}

	logger.Info("upload created", zap.String("file_id", result.File.ID.String()), zap.Int64("size", result.File.Size))

	return &filev1.CreateUploadResponse{
		File:      toProtoFile(result.File),
		UploadUrl: result.URL,
		ExpiresAt: timestamppb.New(result.ExpiresAt),
	}, nil
}

// ConfirmUpload разбирает ID файла и пользователя и подтверждает загрузку через сервис,
// передавая признак роли admin или dispatcher для проверки доступа.
func (h *Handler) ConfirmUpload(ctx context.Context, req *filev1.ConfirmUploadRequest) (*filev1.ConfirmUploadResponse, error) {
	fileID, actorID, err := parseFileAndActor(req.GetFileId(), req.GetActorUserId())

	if err != nil {
		return nil, invalidArgument(err)
	}

	file, err := h.service.Confirm(ctx, fileID, actorID, hasPrivilegedRole(req.GetActorRoles()))

	if err != nil {
		return nil, serviceError(err)
	}

	return &filev1.ConfirmUploadResponse{File: toProtoFile(file)}, nil
}

// LinkFile разбирает UUID файла, пользователя и ресурса и передаёт связь сервису.
// Ошибки UUID возвращает как InvalidArgument, ошибки сервиса — через serviceError.
func (h *Handler) LinkFile(ctx context.Context, req *filev1.LinkFileRequest) (*filev1.LinkFileResponse, error) {
	if !h.canLink(ctx, req.GetActorRoles()) {
		return nil, status.Error(codes.PermissionDenied, "resource linking requires the report workflow or admin")
	}
	if req.GetResourceType() != "report" && req.GetResourceType() != "work_report" {
		return nil, status.Error(codes.InvalidArgument, "unsupported resource type")
	}
	fileID, actorID, err := parseFileAndActor(req.GetFileId(), req.GetActorUserId())

	if err != nil {
		return nil, invalidArgument(err)
	}

	resourceID, err := parseUUID(req.GetResourceId(), "resource_id")

	if err != nil {
		return nil, invalidArgument(err)
	}

	file, err := h.service.Link(ctx, fileID, actorID, hasPrivilegedRole(req.GetActorRoles()), models.LinkInput{
		ResourceType: req.GetResourceType(),
		ResourceID:   resourceID,
	})

	if err != nil {
		return nil, serviceError(err)
	}

	return &filev1.LinkFileResponse{File: toProtoFile(file)}, nil
}

// canLink разрешает связывание файла для администратора или по доверенному токену отчета.
func (h *Handler) canLink(ctx context.Context, roles []string) bool {
	for _, role := range roles {
		if role == "admin" {
			return true
		}
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-report-link-token")
	return h.linkToken != "" && len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(h.linkToken)) == 1
}

// GetDownloadURL запрашивает у сервиса ссылку скачивания с данными пользователя
// и признаком привилегированной роли; возвращает файл, URL и срок действия.
func (h *Handler) GetDownloadURL(ctx context.Context, req *filev1.GetDownloadURLRequest) (*filev1.GetDownloadURLResponse, error) {
	fileID, actorID, err := parseFileAndActor(req.GetFileId(), req.GetActorUserId())

	if err != nil {
		return nil, invalidArgument(err)
	}

	result, err := h.service.Download(ctx, fileID, actorID, hasPrivilegedRole(req.GetActorRoles()))

	if err != nil {
		return nil, serviceError(err)
	}

	return &filev1.GetDownloadURLResponse{
		File:        toProtoFile(result.File),
		DownloadUrl: result.URL,
		ExpiresAt:   timestamppb.New(result.ExpiresAt),
	}, nil
}

// ListResourceFiles разбирает UUID ресурса и пользователя, передаёт проверку
// доступа сервису и преобразует список файлов в protobuf.
func (h *Handler) ListResourceFiles(ctx context.Context, req *filev1.ListResourceFilesRequest) (*filev1.ListResourceFilesResponse, error) {
	resourceID, err := parseUUID(req.GetResourceId(), "resource_id")

	if err != nil {
		return nil, invalidArgument(err)
	}

	actorID, err := parseUUID(req.GetActorUserId(), "actor_user_id")

	if err != nil {
		return nil, invalidArgument(err)
	}

	files, err := h.service.List(
		ctx,
		req.GetResourceType(),
		resourceID,
		actorID,
		hasPrivilegedRole(req.GetActorRoles()),
	)

	if err != nil {
		return nil, serviceError(err)
	}

	result := make([]*filev1.File, 0, len(files))
	for _, file := range files {
		result = append(result, toProtoFile(file))
	}

	return &filev1.ListResourceFilesResponse{Files: result}, nil
}

// DeleteFile разбирает ID файла и пользователя и вызывает удаление в сервисе
// с признаком привилегированной роли; при успехе возвращает пустой ответ.
func (h *Handler) DeleteFile(ctx context.Context, req *filev1.DeleteFileRequest) (*filev1.DeleteFileResponse, error) {
	fileID, actorID, err := parseFileAndActor(req.GetFileId(), req.GetActorUserId())

	if err != nil {
		return nil, invalidArgument(err)
	}

	if err := h.service.Delete(ctx, fileID, actorID, hasPrivilegedRole(req.GetActorRoles())); err != nil {
		return nil, serviceError(err)
	}

	return &filev1.DeleteFileResponse{}, nil
}

// parseFileAndActor разбирает UUID файла и пользователя в этом порядке;
// при первой ошибке возвращает два uuid.Nil и ошибку с именем поля.
func parseFileAndActor(fileID, actorID string) (uuid.UUID, uuid.UUID, error) {
	parsedFileID, err := parseUUID(fileID, "file_id")

	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	parsedActorID, err := parseUUID(actorID, "actor_user_id")

	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	return parsedFileID, parsedActorID, nil
}

// parseUUID разбирает UUID и добавляет имя field к ошибке формата.
func parseUUID(value, field string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)

	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid %s: %w", field, err)
	}

	return parsed, nil
}

// hasPrivilegedRole распознаёт точные значения admin и dispatcher без нормализации.
func hasPrivilegedRole(roles []string) bool {
	for _, role := range roles {

		if role == "admin" || role == "dispatcher" {
			return true
		}

	}
	return false
}

// invalidArgument преобразует ненулевую ошибку в gRPC InvalidArgument с её текстом.
func invalidArgument(err error) error {
	return status.Error(codes.InvalidArgument, err.Error())
}

// serviceError переводит ошибки отсутствия файла, таймаута, доступа и валидации
// в соответствующие коды gRPC; остальные ошибки даёт как FailedPrecondition.
func serviceError(err error) error {
	switch {
	case service.IsNotFound(err):
		return status.Error(codes.NotFound, "file not found")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	case errors.Is(err, models.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, models.ErrValidation):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.FailedPrecondition, err.Error())
	}
}

// toProtoFile преобразует файл в protobuf с временными метками и необязательной
// связью ресурса; для nil возвращает nil.
func toProtoFile(file *models.File) *filev1.File {

	if file == nil {
		return nil
	}

	result := &filev1.File{
		Id:          file.ID.String(),
		OwnerUserId: file.OwnerUserID.String(),
		Name:        file.Name,
		ContentType: file.ContentType,
		Size:        file.Size,
		Checksum:    file.Checksum,
		Status:      toProtoStatus(file.Status),
		CreatedAt:   timestamppb.New(file.CreatedAt),
		UpdatedAt:   timestamppb.New(file.UpdatedAt),
	}

	if file.ResourceType != nil {
		result.ResourceType = file.ResourceType
	}

	if file.ResourceID != nil {
		resourceID := file.ResourceID.String()
		result.ResourceId = &resourceID
	}

	return result
}

// toProtoStatus преобразует статус файла в protobuf; неизвестный даёт UNSPECIFIED.
func toProtoStatus(fileStatus models.Status) filev1.FileStatus {
	switch fileStatus {
	case models.StatusPendingUpload:
		return filev1.FileStatus_FILE_STATUS_PENDING_UPLOAD
	case models.StatusUploaded:
		return filev1.FileStatus_FILE_STATUS_UPLOADED
	case models.StatusLinked:
		return filev1.FileStatus_FILE_STATUS_LINKED
	case models.StatusDeleted:
		return filev1.FileStatus_FILE_STATUS_DELETED
	case models.StatusQuarantined:
		return filev1.FileStatus_FILE_STATUS_QUARANTINED
	default:
		return filev1.FileStatus_FILE_STATUS_UNSPECIFIED
	}
}
