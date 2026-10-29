package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"profile/models"
	"profile/pkg"
	"profile/src/core/service"
)

type ProfileHandler struct {
	profilev1.UnimplementedProfileServiceServer
	service *service.Service
	logger  *zap.Logger
}

type actorContext struct {
	UserID *uuid.UUID
	Roles  []string
}

// NewProfileHandler создаёт gRPC-обработчик профилей; nil logger заменяет журналом без вывода.
func NewProfileHandler(service *service.Service, logger *zap.Logger) *ProfileHandler {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &ProfileHandler{service: service, logger: logger}
}

// CreateUserProfile проверяет UUID пользователя и необязательного аватара,
// преобразует способ связи и передаёт создание с контекстом доступа сервису.
func (h *ProfileHandler) CreateUserProfile(ctx context.Context, req *profilev1.CreateUserProfileRequest) (*profilev1.CreateUserProfileResponse, error) {
	logger := h.requestLogger(ctx, "CreateUserProfile")

	userID, err := parseUUID(req.GetUserId(), "user_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "CreateUserProfile", err)
	}

	avatarFileID, err := stringPtrToUUIDPtr(req.AvatarFileId, "avatar_file_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "CreateUserProfile", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.CreateUserProfile(ctx, &models.CreateUserProfileInput{
		UserID:                 userID,
		FullName:               req.GetFullName(),
		Phone:                  req.Phone,
		AvatarFileID:           avatarFileID,
		PreferredContactMethod: FromProtoPreferredContactMethod(req.GetPreferredContactMethod()),
		ActorUserID:            actor.UserID,
		ActorRoles:             actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "CreateUserProfile", err)
	}

	return &profilev1.CreateUserProfileResponse{UserProfile: ToProtoUserProfile(res.UserProfile)}, nil
}

// GetUserProfileByID разбирает UUID профиля и передаёт пользователя и роли
// из метаданных сервису для проверки доступа; возвращает профиль в protobuf.
func (h *ProfileHandler) GetUserProfileByID(ctx context.Context, req *profilev1.GetUserProfileByIDRequest) (*profilev1.GetUserProfileByIDResponse, error) {
	logger := h.requestLogger(ctx, "GetUserProfileByID")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "GetUserProfileByID", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetUserProfileByID(ctx, &models.GetUserProfileByIDInput{ID: id, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "GetUserProfileByID", err)
	}

	return &profilev1.GetUserProfileByIDResponse{UserProfile: ToProtoUserProfile(res.UserProfile)}, nil
}

// GetUserProfileByUserID разбирает UUID пользователя и запрашивает профиль
// с контекстом доступа из метаданных, преобразуя результат и ошибку в gRPC.
func (h *ProfileHandler) GetUserProfileByUserID(ctx context.Context, req *profilev1.GetUserProfileByUserIDRequest) (*profilev1.GetUserProfileByUserIDResponse, error) {
	logger := h.requestLogger(ctx, "GetUserProfileByUserID")
	userID, err := parseUUID(req.GetUserId(), "user_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "GetUserProfileByUserID", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetUserProfileByUserID(ctx, &models.GetUserProfileByUserIDInput{UserID: userID, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "GetUserProfileByUserID", err)
	}

	return &profilev1.GetUserProfileByUserIDResponse{UserProfile: ToProtoUserProfile(res.UserProfile)}, nil
}

// GetMyUserProfile запрашивает профиль пользователя из входящих метаданных;
// обязательность и допустимость пользователя проверяет сервис.
func (h *ProfileHandler) GetMyUserProfile(ctx context.Context, _ *profilev1.GetMyUserProfileRequest) (*profilev1.GetMyUserProfileResponse, error) {
	logger := h.requestLogger(ctx, "GetMyUserProfile")
	actor := actorFromContext(ctx)
	res, err := h.service.GetMyUserProfile(ctx, &models.GetMyUserProfileInput{ActorUserID: actor.UserID})

	if err != nil {
		return nil, h.logAndMapError(logger, "GetMyUserProfile", err)
	}

	return &profilev1.GetMyUserProfileResponse{UserProfile: ToProtoUserProfile(res.UserProfile)}, nil
}

// ListUserProfiles преобразует поиск, пагинацию и заданную сортировку и передаёт
// контекст доступа сервису; возвращает страницу профилей с общим счётчиком.
func (h *ProfileHandler) ListUserProfiles(ctx context.Context, req *profilev1.ListUserProfilesRequest) (*profilev1.ListUserProfilesResponse, error) {
	logger := h.requestLogger(ctx, "ListUserProfiles")
	actor := actorFromContext(ctx)
	in := &models.ListUserProfilesInput{
		Query:       req.Query,
		Limit:       req.GetLimit(),
		Offset:      req.GetOffset(),
		ActorUserID: actor.UserID,
		ActorRoles:  actor.Roles,
	}

	if req.SortBy != nil {
		in.SortBy = FromProtoUserProfileSortBy(req.GetSortBy())
	}

	if req.SortOrder != nil {
		in.SortOrder = FromProtoSortOrder(req.GetSortOrder())
	}

	res, err := h.service.ListUserProfiles(ctx, in)

	if err != nil {
		return nil, h.logAndMapError(logger, "ListUserProfiles", err)
	}

	return &profilev1.ListUserProfilesResponse{UserProfiles: toProtoUserProfiles(res.UserProfiles), Total: res.Total}, nil
}

// UpdateUserProfile проверяет UUID профиля и аватара, сохраняет необязательность
// полей и передаёт флаги очистки телефона и аватара с контекстом доступа сервису.
func (h *ProfileHandler) UpdateUserProfile(ctx context.Context, req *profilev1.UpdateUserProfileRequest) (*profilev1.UpdateUserProfileResponse, error) {
	logger := h.requestLogger(ctx, "UpdateUserProfile")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateUserProfile", err)
	}

	avatarFileID, err := stringPtrToUUIDPtr(req.AvatarFileId, "avatar_file_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateUserProfile", err)
	}

	var contactMethod *models.PreferredContactMethod

	if req.PreferredContactMethod != nil {
		value := FromProtoPreferredContactMethod(req.GetPreferredContactMethod())
		contactMethod = &value
	}

	actor := actorFromContext(ctx)
	res, err := h.service.UpdateUserProfile(ctx, &models.UpdateUserProfileInput{
		ID:                     id,
		FullName:               req.FullName,
		Phone:                  req.Phone,
		ClearPhone:             req.GetClearPhone(),
		AvatarFileID:           avatarFileID,
		ClearAvatarFileID:      req.GetClearAvatarFileId(),
		PreferredContactMethod: contactMethod,
		ActorUserID:            actor.UserID,
		ActorRoles:             actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateUserProfile", err)
	}

	return &profilev1.UpdateUserProfileResponse{UserProfile: ToProtoUserProfile(res.UserProfile)}, nil
}

// CreateWorkProfile разбирает UUID личного профиля и ведомства и передаёт
// должность, табельный номер и контекст доступа сервису; возвращает подробный профиль.
func (h *ProfileHandler) CreateWorkProfile(ctx context.Context, req *profilev1.CreateWorkProfileRequest) (*profilev1.CreateWorkProfileResponse, error) {
	logger := h.requestLogger(ctx, "CreateWorkProfile")
	userProfileID, departmentID, err := parseTwoUUIDs(req.GetUserProfileId(), "user_profile_id", req.GetDepartmentId(), "department_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "CreateWorkProfile", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.CreateWorkProfile(ctx, &models.CreateWorkProfileInput{
		UserProfileID:  userProfileID,
		DepartmentID:   departmentID,
		EmployeeNumber: req.EmployeeNumber,
		Position:       req.GetPosition(),
		ActorUserID:    actor.UserID,
		ActorRoles:     actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "CreateWorkProfile", err)
	}

	return &profilev1.CreateWorkProfileResponse{Details: ToProtoWorkProfileDetails(res.Details)}, nil
}

// GetWorkProfileByID проверяет UUID рабочего профиля и передаёт контекст доступа
// сервису; возвращает связанные рабочий и пользовательский профили.
func (h *ProfileHandler) GetWorkProfileByID(ctx context.Context, req *profilev1.GetWorkProfileByIDRequest) (*profilev1.GetWorkProfileByIDResponse, error) {
	logger := h.requestLogger(ctx, "GetWorkProfileByID")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "GetWorkProfileByID", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetWorkProfileByID(ctx, &models.GetWorkProfileByIDInput{ID: id, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "GetWorkProfileByID", err)
	}

	return &profilev1.GetWorkProfileByIDResponse{Details: ToProtoWorkProfileDetails(res.Details)}, nil
}

// GetWorkProfileByUserID разбирает UUID пользователя и передаёт чтение рабочего
// профиля с контекстом доступа сервису; возвращает подробные данные в protobuf.
func (h *ProfileHandler) GetWorkProfileByUserID(ctx context.Context, req *profilev1.GetWorkProfileByUserIDRequest) (*profilev1.GetWorkProfileByUserIDResponse, error) {
	logger := h.requestLogger(ctx, "GetWorkProfileByUserID")
	userID, err := parseUUID(req.GetUserId(), "user_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "GetWorkProfileByUserID", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetWorkProfileByUserID(ctx, &models.GetWorkProfileByUserIDInput{UserID: userID, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "GetWorkProfileByUserID", err)
	}

	return &profilev1.GetWorkProfileByUserIDResponse{Details: ToProtoWorkProfileDetails(res.Details)}, nil
}

// ListWorkProfiles проверяет необязательное ведомство, преобразует фильтры,
// сортировку и пагинацию и возвращает страницу со счётчиком через сервис проверки
// доступа. UNSPECIFIED-статус не добавляет в фильтр.
func (h *ProfileHandler) ListWorkProfiles(ctx context.Context, req *profilev1.ListWorkProfilesRequest) (*profilev1.ListWorkProfilesResponse, error) {
	logger := h.requestLogger(ctx, "ListWorkProfiles")
	departmentID, err := stringPtrToUUIDPtr(req.DepartmentId, "department_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "ListWorkProfiles", err)
	}

	var workStatus *models.WorkProfileStatus

	if req.Status != nil && req.GetStatus() != profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_UNSPECIFIED {
		value := FromProtoWorkProfileStatus(req.GetStatus())
		workStatus = &value
	}

	actor := actorFromContext(ctx)
	in := &models.ListWorkProfilesInput{
		DepartmentID: departmentID,
		Status:       workStatus,
		Query:        req.Query,
		Limit:        req.GetLimit(),
		Offset:       req.GetOffset(),
		ActorUserID:  actor.UserID,
		ActorRoles:   actor.Roles,
	}

	if req.SortBy != nil {
		in.SortBy = FromProtoWorkProfileSortBy(req.GetSortBy())
	}

	if req.SortOrder != nil {
		in.SortOrder = FromProtoSortOrder(req.GetSortOrder())
	}

	res, err := h.service.ListWorkProfiles(ctx, in)

	if err != nil {
		return nil, h.logAndMapError(logger, "ListWorkProfiles", err)
	}

	return &profilev1.ListWorkProfilesResponse{WorkProfiles: toProtoWorkProfileDetails(res.WorkProfiles), Total: res.Total}, nil
}

// UpdateWorkProfile разбирает UUID и передаёт заданные должность и табельный номер,
// флаг очистки номера и контекст доступа сервису обновления.
func (h *ProfileHandler) UpdateWorkProfile(ctx context.Context, req *profilev1.UpdateWorkProfileRequest) (*profilev1.UpdateWorkProfileResponse, error) {
	logger := h.requestLogger(ctx, "UpdateWorkProfile")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateWorkProfile", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.UpdateWorkProfile(ctx, &models.UpdateWorkProfileInput{
		ID:                  id,
		EmployeeNumber:      req.EmployeeNumber,
		ClearEmployeeNumber: req.GetClearEmployeeNumber(),
		Position:            req.Position,
		ActorUserID:         actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateWorkProfile", err)
	}

	return &profilev1.UpdateWorkProfileResponse{Details: ToProtoWorkProfileDetails(res.Details)}, nil
}

// DeactivateWorkProfile проверяет UUID и передаёт причину деактивации
// с пользователем и ролями из метаданных сервису.
func (h *ProfileHandler) DeactivateWorkProfile(ctx context.Context, req *profilev1.DeactivateWorkProfileRequest) (*profilev1.DeactivateWorkProfileResponse, error) {
	logger := h.requestLogger(ctx, "DeactivateWorkProfile")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "DeactivateWorkProfile", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.DeactivateWorkProfile(ctx, &models.DeactivateWorkProfileInput{ID: id, Reason: req.GetReason(), ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "DeactivateWorkProfile", err)
	}

	return &profilev1.DeactivateWorkProfileResponse{Details: ToProtoWorkProfileDetails(res.Details)}, nil
}

// ChangeWorkProfileDepartment проверяет UUID профиля и нового ведомства и передаёт
// изменение с причиной и контекстом доступа сервису.
func (h *ProfileHandler) ChangeWorkProfileDepartment(ctx context.Context, req *profilev1.ChangeWorkProfileDepartmentRequest) (*profilev1.ChangeWorkProfileDepartmentResponse, error) {
	logger := h.requestLogger(ctx, "ChangeWorkProfileDepartment")
	id, departmentID, err := parseTwoUUIDs(req.GetId(), "id", req.GetDepartmentId(), "department_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "ChangeWorkProfileDepartment", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ChangeWorkProfileDepartment(ctx, &models.ChangeWorkProfileDepartmentInput{
		ID:           id,
		DepartmentID: departmentID,
		Reason:       req.GetReason(),
		ActorUserID:  actor.UserID,
		ActorRoles:   actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "ChangeWorkProfileDepartment", err)
	}

	return &profilev1.ChangeWorkProfileDepartmentResponse{Details: ToProtoWorkProfileDetails(res.Details)}, nil
}

// SetWorkProfileStatus разбирает UUID и преобразует целевой статус профиля;
// проверку перехода и доступа передаёт сервису вместе с причиной изменения.
func (h *ProfileHandler) SetWorkProfileStatus(ctx context.Context, req *profilev1.SetWorkProfileStatusRequest) (*profilev1.SetWorkProfileStatusResponse, error) {
	logger := h.requestLogger(ctx, "SetWorkProfileStatus")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "SetWorkProfileStatus", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.SetWorkProfileStatus(ctx, &models.SetWorkProfileStatusInput{
		ID:          id,
		Status:      FromProtoWorkProfileStatus(req.GetStatus()),
		Reason:      req.GetReason(),
		ActorUserID: actor.UserID,
		ActorRoles:  actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "SetWorkProfileStatus", err)
	}

	return &profilev1.SetWorkProfileStatusResponse{Details: ToProtoWorkProfileDetails(res.Details)}, nil
}

// GetWorkProfileStatusHistory проверяет UUID профиля и передаёт пагинацию и контекст
// доступа сервису; возвращает страницу истории статусов с общим счётчиком.
func (h *ProfileHandler) GetWorkProfileStatusHistory(ctx context.Context, req *profilev1.GetWorkProfileStatusHistoryRequest) (*profilev1.GetWorkProfileStatusHistoryResponse, error) {
	logger := h.requestLogger(ctx, "GetWorkProfileStatusHistory")
	workProfileID, err := parseUUID(req.GetWorkProfileId(), "work_profile_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "GetWorkProfileStatusHistory", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GetWorkProfileStatusHistory(ctx, &models.GetWorkProfileStatusHistoryInput{
		WorkProfileID: workProfileID,
		Limit:         req.GetLimit(),
		Offset:        req.GetOffset(),
		ActorUserID:   actor.UserID,
		ActorRoles:    actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "GetWorkProfileStatusHistory", err)
	}

	return &profilev1.GetWorkProfileStatusHistoryResponse{History: toProtoStatusHistory(res.History), Total: res.Total}, nil
}

// ResolveWorkingDepartment разбирает UUID пользователя и возвращает определённые
// сервисом профили, ведомство, рабочий статус и допуск к работе без проверки ролей в хендлере.
func (h *ProfileHandler) ResolveWorkingDepartment(ctx context.Context, req *profilev1.ResolveWorkingDepartmentRequest) (*profilev1.ResolveWorkingDepartmentResponse, error) {
	logger := h.requestLogger(ctx, "ResolveWorkingDepartment")
	userID, err := parseUUID(req.GetUserId(), "user_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "ResolveWorkingDepartment", err)
	}

	res, err := h.service.ResolveWorkingDepartment(ctx, &models.ResolveWorkingDepartmentInput{UserID: userID})

	if err != nil {
		return nil, h.logAndMapError(logger, "ResolveWorkingDepartment", err)
	}

	return &profilev1.ResolveWorkingDepartmentResponse{
		UserProfileId:     res.UserProfileID.String(),
		WorkProfileId:     res.WorkProfileID.String(),
		UserId:            res.UserID.String(),
		DepartmentId:      res.DepartmentID.String(),
		WorkProfileStatus: ToProtoWorkProfileStatus(res.WorkProfileStatus),
		CanOperate:        res.CanOperate,
	}, nil
}

// CheckProfileCanJoinBrigade проверяет необязательные UUID пользователя и рабочего
// профиля и обязательный UUID ведомства бригады; возвращает допуск, причину
// и канонические ID из сервиса без самостоятельной проверки ролей.
func (h *ProfileHandler) CheckProfileCanJoinBrigade(ctx context.Context, req *profilev1.CheckProfileCanJoinBrigadeRequest) (*profilev1.CheckProfileCanJoinBrigadeResponse, error) {
	logger := h.requestLogger(ctx, "CheckProfileCanJoinBrigade")
	userID, err := stringPtrToUUIDPtr(req.UserId, "user_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "CheckProfileCanJoinBrigade", err)
	}

	workProfileID, err := stringPtrToUUIDPtr(req.WorkProfileId, "work_profile_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "CheckProfileCanJoinBrigade", err)
	}

	departmentID, err := parseUUID(req.GetBrigadeDepartmentId(), "brigade_department_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "CheckProfileCanJoinBrigade", err)
	}

	res, err := h.service.CheckProfileCanJoinBrigade(ctx, &models.CheckProfileCanJoinBrigadeInput{UserID: userID, WorkProfileID: workProfileID, BrigadeDepartmentID: departmentID})

	if err != nil {
		return nil, h.logAndMapError(logger, "CheckProfileCanJoinBrigade", err)
	}

	return &profilev1.CheckProfileCanJoinBrigadeResponse{
		UserProfileId: res.UserProfileID.String(),
		WorkProfileId: res.WorkProfileID.String(),
		UserId:        res.UserID.String(),
		DepartmentId:  res.DepartmentID.String(),
		Allowed:       res.Allowed,
		Reason:        ToProtoCanJoinBrigadeReason(res.Reason),
	}, nil
}

// CreateCertificationType передаёт описание типа сертификата, срок действия,
// требование файла и контекст доступа сервису создания.
func (h *ProfileHandler) CreateCertificationType(ctx context.Context, req *profilev1.CreateCertificationTypeRequest) (*profilev1.CreateCertificationTypeResponse, error) {
	logger := h.requestLogger(ctx, "CreateCertificationType")
	actor := actorFromContext(ctx)
	res, err := h.service.CreateCertificationType(ctx, &models.CreateCertificationTypeInput{
		Code:                req.GetCode(),
		Name:                req.GetName(),
		Description:         req.Description,
		DefaultValidityDays: req.DefaultValidityDays,
		RequiresFile:        req.GetRequiresFile(),
		ActorUserID:         actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "CreateCertificationType", err)
	}

	return &profilev1.CreateCertificationTypeResponse{CertificationType: ToProtoCertificationType(res.CertificationType)}, nil
}

// UpdateCertificationType проверяет UUID и передаёт заданные поля типа сертификата,
// флаги очистки описания и срока действия и контекст доступа сервису.
func (h *ProfileHandler) UpdateCertificationType(ctx context.Context, req *profilev1.UpdateCertificationTypeRequest) (*profilev1.UpdateCertificationTypeResponse, error) {
	logger := h.requestLogger(ctx, "UpdateCertificationType")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateCertificationType", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.UpdateCertificationType(ctx, &models.UpdateCertificationTypeInput{
		ID:                  id,
		Code:                req.Code,
		Name:                req.Name,
		Description:         req.Description,
		ClearDescription:    req.GetClearDescription(),
		DefaultValidityDays: req.DefaultValidityDays,
		ClearValidityDays:   req.GetClearValidityDays(),
		RequiresFile:        req.RequiresFile,
		Active:              req.Active,
		ActorUserID:         actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "UpdateCertificationType", err)
	}

	return &profilev1.UpdateCertificationTypeResponse{CertificationType: ToProtoCertificationType(res.CertificationType)}, nil
}

// ListCertificationTypes передаёт поиск, активность, пагинацию и контекст доступа
// сервису; возвращает страницу типов сертификатов с общим счётчиком.
func (h *ProfileHandler) ListCertificationTypes(ctx context.Context, req *profilev1.ListCertificationTypesRequest) (*profilev1.ListCertificationTypesResponse, error) {
	logger := h.requestLogger(ctx, "ListCertificationTypes")
	actor := actorFromContext(ctx)
	res, err := h.service.ListCertificationTypes(ctx, &models.ListCertificationTypesInput{
		Active:      req.Active,
		Query:       req.Query,
		Limit:       req.GetLimit(),
		Offset:      req.GetOffset(),
		ActorUserID: actor.UserID,
		ActorRoles:  actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "ListCertificationTypes", err)
	}

	return &profilev1.ListCertificationTypesResponse{CertificationTypes: toProtoCertificationTypes(res.CertificationTypes), Total: res.Total}, nil
}

// AddCertificationTypeSkill разбирает UUID типа и навыка и передаёт создание связи
// с уровнем владения и контекстом доступа сервису.
func (h *ProfileHandler) AddCertificationTypeSkill(ctx context.Context, req *profilev1.AddCertificationTypeSkillRequest) (*profilev1.AddCertificationTypeSkillResponse, error) {
	logger := h.requestLogger(ctx, "AddCertificationTypeSkill")
	typeID, skillID, err := parseTwoUUIDs(req.GetCertificationTypeId(), "certification_type_id", req.GetSkillId(), "skill_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "AddCertificationTypeSkill", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.AddCertificationTypeSkill(ctx, &models.AddCertificationTypeSkillInput{
		CertificationTypeID: typeID,
		SkillID:             skillID,
		ProficiencyLevel:    req.ProficiencyLevel,
		ActorUserID:         actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "AddCertificationTypeSkill", err)
	}

	return &profilev1.AddCertificationTypeSkillResponse{CertificationTypeSkill: ToProtoCertificationTypeSkill(res.CertificationTypeSkill)}, nil
}

// RemoveCertificationTypeSkill проверяет UUID типа и навыка и передаёт удаление
// связи с контекстом доступа сервису; при успехе возвращает Success=true.
func (h *ProfileHandler) RemoveCertificationTypeSkill(ctx context.Context, req *profilev1.RemoveCertificationTypeSkillRequest) (*profilev1.RemoveCertificationTypeSkillResponse, error) {
	logger := h.requestLogger(ctx, "RemoveCertificationTypeSkill")
	typeID, skillID, err := parseTwoUUIDs(req.GetCertificationTypeId(), "certification_type_id", req.GetSkillId(), "skill_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "RemoveCertificationTypeSkill", err)
	}

	actor := actorFromContext(ctx)
	err = h.service.RemoveCertificationTypeSkill(ctx, &models.RemoveCertificationTypeSkillInput{CertificationTypeID: typeID, SkillID: skillID, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "RemoveCertificationTypeSkill", err)
	}

	return &profilev1.RemoveCertificationTypeSkillResponse{Success: true}, nil
}

// ListCertificationTypeSkills разбирает UUID типа и передаёт фильтр ActiveOnly
// и контекст доступа сервису; возвращает связи с навыками в protobuf.
func (h *ProfileHandler) ListCertificationTypeSkills(ctx context.Context, req *profilev1.ListCertificationTypeSkillsRequest) (*profilev1.ListCertificationTypeSkillsResponse, error) {
	logger := h.requestLogger(ctx, "ListCertificationTypeSkills")
	typeID, err := parseUUID(req.GetCertificationTypeId(), "certification_type_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "ListCertificationTypeSkills", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListCertificationTypeSkills(ctx, &models.ListCertificationTypeSkillsInput{
		CertificationTypeID: typeID,
		ActiveOnly:          req.GetActiveOnly(),
		ActorUserID:         actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "ListCertificationTypeSkills", err)
	}

	return &profilev1.ListCertificationTypeSkillsResponse{Skills: toProtoCertificationTypeSkills(res.Skills)}, nil
}

// UploadWorkProfileCertification проверяет UUID профиля, типа и необязательного
// файла, преобразует даты выдачи и окончания и передаёт регистрацию сертификата
// с контекстом доступа сервису; содержимое файла через этот RPC не передаётся.
func (h *ProfileHandler) UploadWorkProfileCertification(ctx context.Context, req *profilev1.UploadWorkProfileCertificationRequest) (*profilev1.UploadWorkProfileCertificationResponse, error) {
	logger := h.requestLogger(ctx, "UploadWorkProfileCertification")
	workProfileID, typeID, err := parseTwoUUIDs(req.GetWorkProfileId(), "work_profile_id", req.GetCertificationTypeId(), "certification_type_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "UploadWorkProfileCertification", err)
	}

	fileID, err := stringPtrToUUIDPtr(req.CertificateFileId, "certificate_file_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "UploadWorkProfileCertification", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.UploadWorkProfileCertification(ctx, &models.UploadWorkProfileCertificationInput{
		WorkProfileID:       workProfileID,
		CertificationTypeID: typeID,
		CertificateNumber:   req.CertificateNumber,
		Issuer:              req.Issuer,
		IssuedAt:            FromProtoTimestamp(req.GetIssuedAt()),
		ExpiresAt:           FromProtoTimestamp(req.GetExpiresAt()),
		CertificateFileID:   fileID,
		ActorUserID:         actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "UploadWorkProfileCertification", err)
	}

	return &profilev1.UploadWorkProfileCertificationResponse{Certification: ToProtoWorkProfileCertification(res.Certification)}, nil
}

// VerifyWorkProfileCertification разбирает UUID сертификата и передаёт проверку
// с контекстом доступа сервису; возвращает сертификат и выдачи навыков из результата.
func (h *ProfileHandler) VerifyWorkProfileCertification(ctx context.Context, req *profilev1.VerifyWorkProfileCertificationRequest) (*profilev1.VerifyWorkProfileCertificationResponse, error) {
	logger := h.requestLogger(ctx, "VerifyWorkProfileCertification")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "VerifyWorkProfileCertification", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.VerifyWorkProfileCertification(ctx, &models.VerifyWorkProfileCertificationInput{ID: id, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "VerifyWorkProfileCertification", err)
	}

	return &profilev1.VerifyWorkProfileCertificationResponse{
		Certification: ToProtoWorkProfileCertification(res.Certification),
		SkillGrants:   toProtoSkillGrants(res.SkillGrants),
	}, nil
}

// RejectWorkProfileCertification проверяет UUID и передаёт причину отклонения
// и контекст доступа сервису; возвращает обновлённый сертификат в protobuf.
func (h *ProfileHandler) RejectWorkProfileCertification(ctx context.Context, req *profilev1.RejectWorkProfileCertificationRequest) (*profilev1.RejectWorkProfileCertificationResponse, error) {
	logger := h.requestLogger(ctx, "RejectWorkProfileCertification")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "RejectWorkProfileCertification", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.RejectWorkProfileCertification(ctx, &models.RejectWorkProfileCertificationInput{
		ID:              id,
		RejectionReason: req.GetRejectionReason(),
		ActorUserID:     actor.UserID,
		ActorRoles:      actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "RejectWorkProfileCertification", err)
	}

	return &profilev1.RejectWorkProfileCertificationResponse{Certification: ToProtoWorkProfileCertification(res.Certification)}, nil
}

// RevokeWorkProfileCertification проверяет UUID и передаёт отзыв с причиной
// и контекстом доступа сервису; возвращает сертификат и список отозванных выдач навыков.
func (h *ProfileHandler) RevokeWorkProfileCertification(ctx context.Context, req *profilev1.RevokeWorkProfileCertificationRequest) (*profilev1.RevokeWorkProfileCertificationResponse, error) {
	logger := h.requestLogger(ctx, "RevokeWorkProfileCertification")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "RevokeWorkProfileCertification", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.RevokeWorkProfileCertification(ctx, &models.RevokeWorkProfileCertificationInput{ID: id, Reason: req.GetReason(), ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "RevokeWorkProfileCertification", err)
	}

	return &profilev1.RevokeWorkProfileCertificationResponse{
		Certification: ToProtoWorkProfileCertification(res.Certification),
		RevokedGrants: toProtoSkillGrants(res.RevokedGrants),
	}, nil
}

// ExpireWorkProfileCertifications передаёт лимит и контекст доступа сервису
// обработки истёкших сертификатов; возвращает обработанные сертификаты и отозванные навыки.
func (h *ProfileHandler) ExpireWorkProfileCertifications(ctx context.Context, req *profilev1.ExpireWorkProfileCertificationsRequest) (*profilev1.ExpireWorkProfileCertificationsResponse, error) {
	logger := h.requestLogger(ctx, "ExpireWorkProfileCertifications")
	actor := actorFromContext(ctx)
	res, err := h.service.ExpireWorkProfileCertifications(ctx, &models.ExpireWorkProfileCertificationsInput{Limit: req.GetLimit(), ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "ExpireWorkProfileCertifications", err)
	}

	return &profilev1.ExpireWorkProfileCertificationsResponse{
		ExpiredCertifications: toProtoCertifications(res.ExpiredCertifications),
		RevokedGrants:         toProtoSkillGrants(res.RevokedGrants),
	}, nil
}

// ListWorkProfileCertifications проверяет UUID профиля и необязательного типа,
// преобразует статус и передаёт пагинацию и контекст доступа сервису.
// UNSPECIFIED-статус пропускает; возвращает страницу сертификатов со счётчиком.
func (h *ProfileHandler) ListWorkProfileCertifications(ctx context.Context, req *profilev1.ListWorkProfileCertificationsRequest) (*profilev1.ListWorkProfileCertificationsResponse, error) {
	logger := h.requestLogger(ctx, "ListWorkProfileCertifications")
	workProfileID, err := parseUUID(req.GetWorkProfileId(), "work_profile_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "ListWorkProfileCertifications", err)
	}

	typeID, err := stringPtrToUUIDPtr(req.CertificationTypeId, "certification_type_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "ListWorkProfileCertifications", err)
	}

	var certStatus *models.CertificationStatus

	if req.Status != nil && req.GetStatus() != profilev1.CertificationStatus_CERTIFICATION_STATUS_UNSPECIFIED {
		value := FromProtoCertificationStatus(req.GetStatus())
		certStatus = &value
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListWorkProfileCertifications(ctx, &models.ListWorkProfileCertificationsInput{
		WorkProfileID:       workProfileID,
		CertificationTypeID: typeID,
		Status:              certStatus,
		Limit:               req.GetLimit(),
		Offset:              req.GetOffset(),
		ActorUserID:         actor.UserID,
		ActorRoles:          actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "ListWorkProfileCertifications", err)
	}

	return &profilev1.ListWorkProfileCertificationsResponse{Certifications: toProtoCertifications(res.Certifications), Total: res.Total}, nil
}

// GrantManualWorkProfileSkill проверяет UUID профиля и навыка, преобразует срок
// и передаёт ручную выдачу с уровнем, причиной и контекстом доступа сервису.
func (h *ProfileHandler) GrantManualWorkProfileSkill(ctx context.Context, req *profilev1.GrantManualWorkProfileSkillRequest) (*profilev1.GrantManualWorkProfileSkillResponse, error) {
	logger := h.requestLogger(ctx, "GrantManualWorkProfileSkill")
	workProfileID, skillID, err := parseTwoUUIDs(req.GetWorkProfileId(), "work_profile_id", req.GetSkillId(), "skill_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "GrantManualWorkProfileSkill", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.GrantManualWorkProfileSkill(ctx, &models.GrantManualWorkProfileSkillInput{
		WorkProfileID:    workProfileID,
		SkillID:          skillID,
		ProficiencyLevel: req.ProficiencyLevel,
		ValidUntil:       FromProtoTimestamp(req.GetValidUntil()),
		Reason:           req.GetReason(),
		ActorUserID:      actor.UserID,
		ActorRoles:       actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "GrantManualWorkProfileSkill", err)
	}

	return &profilev1.GrantManualWorkProfileSkillResponse{SkillGrant: ToProtoWorkProfileSkillGrant(res.SkillGrant)}, nil
}

// RevokeWorkProfileSkillGrant разбирает UUID выдачи навыка и передаёт отзыв
// с причиной и контекстом доступа сервису; возвращает выдачу из результата.
func (h *ProfileHandler) RevokeWorkProfileSkillGrant(ctx context.Context, req *profilev1.RevokeWorkProfileSkillGrantRequest) (*profilev1.RevokeWorkProfileSkillGrantResponse, error) {
	logger := h.requestLogger(ctx, "RevokeWorkProfileSkillGrant")
	id, err := parseUUID(req.GetId(), "id")

	if err != nil {
		return nil, h.logAndMapError(logger, "RevokeWorkProfileSkillGrant", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.RevokeWorkProfileSkillGrant(ctx, &models.RevokeWorkProfileSkillGrantInput{ID: id, Reason: req.GetReason(), ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "RevokeWorkProfileSkillGrant", err)
	}

	return &profilev1.RevokeWorkProfileSkillGrantResponse{SkillGrant: ToProtoWorkProfileSkillGrant(res.SkillGrant)}, nil
}

// ListEffectiveWorkProfileSkills разбирает UUID профиля и передаёт контекст
// доступа сервису; возвращает определённые сервисом действующие выдачи навыков.
func (h *ProfileHandler) ListEffectiveWorkProfileSkills(ctx context.Context, req *profilev1.ListEffectiveWorkProfileSkillsRequest) (*profilev1.ListEffectiveWorkProfileSkillsResponse, error) {
	logger := h.requestLogger(ctx, "ListEffectiveWorkProfileSkills")
	workProfileID, err := parseUUID(req.GetWorkProfileId(), "work_profile_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "ListEffectiveWorkProfileSkills", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.ListEffectiveWorkProfileSkills(ctx, &models.ListEffectiveWorkProfileSkillsInput{WorkProfileID: workProfileID, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "ListEffectiveWorkProfileSkills", err)
	}

	return &profilev1.ListEffectiveWorkProfileSkillsResponse{SkillGrants: toProtoSkillGrants(res.SkillGrants)}, nil
}

// BatchListEffectiveWorkProfileSkills проверяет UUID профилей и передаёт пакетное
// чтение с контекстом доступа сервису; преобразует карту выдач в список protobuf.
// Порядок профилей в ответе не определён из-за обхода map.
func (h *ProfileHandler) BatchListEffectiveWorkProfileSkills(ctx context.Context, req *profilev1.BatchListEffectiveWorkProfileSkillsRequest) (*profilev1.BatchListEffectiveWorkProfileSkillsResponse, error) {
	logger := h.requestLogger(ctx, "BatchListEffectiveWorkProfileSkills")
	workProfileIDs, err := parseUUIDSlice(req.GetWorkProfileIds(), "work_profile_ids")

	if err != nil {
		return nil, h.logAndMapError(logger, "BatchListEffectiveWorkProfileSkills", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.BatchListEffectiveWorkProfileSkills(ctx, &models.BatchListEffectiveWorkProfileSkillsInput{WorkProfileIDs: workProfileIDs, ActorUserID: actor.UserID, ActorRoles: actor.Roles})

	if err != nil {
		return nil, h.logAndMapError(logger, "BatchListEffectiveWorkProfileSkills", err)
	}

	items := make([]*profilev1.EffectiveWorkProfileSkills, 0, len(res.SkillGrantsByWorkProfileID))
	for workProfileID, grants := range res.SkillGrantsByWorkProfileID {
		items = append(items, &profilev1.EffectiveWorkProfileSkills{WorkProfileId: workProfileID.String(), SkillGrants: toProtoSkillGrants(grants)})
	}
	return &profilev1.BatchListEffectiveWorkProfileSkillsResponse{Items: items}, nil
}

// CheckWorkProfileHasSkills проверяет UUID профиля и требуемых навыков и передаёт
// проверку с контекстом доступа сервису; возвращает допуск и недостающие UUID.
func (h *ProfileHandler) CheckWorkProfileHasSkills(ctx context.Context, req *profilev1.CheckWorkProfileHasSkillsRequest) (*profilev1.CheckWorkProfileHasSkillsResponse, error) {
	logger := h.requestLogger(ctx, "CheckWorkProfileHasSkills")
	workProfileID, err := parseUUID(req.GetWorkProfileId(), "work_profile_id")

	if err != nil {
		return nil, h.logAndMapError(logger, "CheckWorkProfileHasSkills", err)
	}

	requiredSkillIDs, err := parseUUIDSlice(req.GetRequiredSkillIds(), "required_skill_ids")

	if err != nil {
		return nil, h.logAndMapError(logger, "CheckWorkProfileHasSkills", err)
	}

	actor := actorFromContext(ctx)
	res, err := h.service.CheckWorkProfileHasSkills(ctx, &models.CheckWorkProfileHasSkillsInput{
		WorkProfileID:    workProfileID,
		RequiredSkillIDs: requiredSkillIDs,
		ActorUserID:      actor.UserID,
		ActorRoles:       actor.Roles,
	})

	if err != nil {
		return nil, h.logAndMapError(logger, "CheckWorkProfileHasSkills", err)
	}

	return &profilev1.CheckWorkProfileHasSkillsResponse{Allowed: res.Allowed, MissingSkillIds: uuidSliceToStrings(res.MissingSkillIDs)}, nil
}

// requestLogger добавляет request ID и имя метода в журнал и записывает получение запроса.
func (h *ProfileHandler) requestLogger(ctx context.Context, method string) *zap.Logger {
	logger := h.logger.With(pkg.RequestIDField(ctx), zap.String("method", method))
	logger.Info("gRPC request received")
	return logger
}

// logAndMapError пишет предупреждение и преобразует ошибку в gRPC с именем метода.
func (h *ProfileHandler) logAndMapError(logger *zap.Logger, method string, err error) error {
	logger.Warn("gRPC request failed", zap.Error(err))
	return profileStatusError(method, err)
}

// parseUUID обрезает крайние пробелы и разбирает UUID;
// неверный формат даёт uuid.Nil и ErrValidation с именем поля.
func parseUUID(value string, field string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(value))

	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: invalid %s: %v", models.ErrValidation, field, err)
	}

	return parsed, nil
}

// parseOptionalUUID возвращает nil для пустой или пробельной строки;
// непустое значение разбирает через parseUUID с обрезкой пробелов.
func parseOptionalUUID(value string, field string) (*uuid.UUID, error) {

	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parsed, err := parseUUID(value, field)

	if err != nil {
		return nil, err
	}

	return &parsed, nil
}

// parseTwoUUIDs последовательно разбирает два UUID с заданными именами полей;
// при любой ошибке возвращает два uuid.Nil и ErrValidation.
func parseTwoUUIDs(firstValue string, firstField string, secondValue string, secondField string) (uuid.UUID, uuid.UUID, error) {
	first, err := parseUUID(firstValue, firstField)

	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	second, err := parseUUID(secondValue, secondField)

	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	return first, second, nil
}

// parseUUIDSlice разбирает UUID с сохранением порядка и повторов;
// первая ошибка даёт nil и ErrValidation, пустой вход — пустой ненулевой срез.
func parseUUIDSlice(values []string, field string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, 0, len(values))
	for _, value := range values {
		parsed, err := parseUUID(value, field)

		if err != nil {
			return nil, err
		}

		result = append(result, parsed)
	}
	return result, nil
}

// uuidSliceToStrings преобразует UUID в строки с сохранением порядка и повторов.
func uuidSliceToStrings(values []uuid.UUID) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

// actorFromContext читает UUID пользователя и роли из метаданных; неверный UUID
// пропускает, роли разделяет запятыми, обрезает пробелы и удаляет пустые элементы,
// сохраняя регистр и повторы.
func actorFromContext(ctx context.Context) actorContext {
	md, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return actorContext{}
	}

	var actor actorContext

	if values := md.Get("x-actor-user-id"); len(values) > 0 && strings.TrimSpace(values[0]) != "" {

		if parsed, err := uuid.Parse(strings.TrimSpace(values[0])); err == nil {
			actor.UserID = &parsed
		}

	}

	if values := md.Get("x-actor-roles"); len(values) > 0 {
		for _, value := range values {
			for _, role := range strings.Split(value, ",") {
				role = strings.TrimSpace(role)

				if role != "" {
					actor.Roles = append(actor.Roles, role)
				}

			}
		}
	}

	return actor
}

// profileStatusError формирует gRPC-ошибку с доменным кодом, именем метода
// и исходным текстом; предназначена для ненулевой ошибки.
func profileStatusError(method string, err error) error {
	return status.Errorf(profileErrorCode(err), "failed %s: %v", method, err)
}

// profileErrorCode сопоставляет ошибки ввода, отсутствия, дубликата и доступа
// кодам gRPC. Незавершённая идемпотентная операция даёт Aborted, ограничения
// состояния — FailedPrecondition, nil — OK, неизвестная ошибка — Internal.
func profileErrorCode(err error) codes.Code {

	if err == nil {
		return codes.OK
	}

	switch {
	case errors.Is(err, models.ErrValidation),
		errors.Is(err, models.ErrInvalidStatus),
		errors.Is(err, models.ErrInvalidCertificationStatus),
		errors.Is(err, models.ErrInvalidContactMethod):
		return codes.InvalidArgument
	case errors.Is(err, models.ErrNotFound),
		errors.Is(err, models.ErrWorkProfileMissing):
		return codes.NotFound
	case errors.Is(err, models.ErrAlreadyExists),
		errors.Is(err, models.ErrIdempotencyConflict):
		return codes.AlreadyExists
	case errors.Is(err, models.ErrPermissionDenied):
		return codes.PermissionDenied
	case errors.Is(err, models.ErrIdempotencyInProgress):
		return codes.Aborted
	case errors.Is(err, models.ErrWorkProfileInactive),
		errors.Is(err, models.ErrDepartmentMismatch),
		errors.Is(err, models.ErrIdempotencyFailed):
		return codes.FailedPrecondition
	default:
		return codes.Internal
	}
}
