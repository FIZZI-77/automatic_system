package handlers

import (
	"context"
	"net/http"
	"time"

	"gateway/models"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/gin-gonic/gin"
)

type ProfileHandler struct {
	profileClient profilev1.ProfileServiceClient
}

func NewProfileHandler(profileClient profilev1.ProfileServiceClient) *ProfileHandler {
	return &ProfileHandler{profileClient: profileClient}
}

func (ph *ProfileHandler) CreateUserProfile(c *gin.Context) {
	var req models.CreateUserProfileRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.CreateUserProfile(profileRequestContext(c), &profilev1.CreateUserProfileRequest{
		UserId:                 req.UserID,
		FullName:               req.FullName,
		Phone:                  req.Phone,
		AvatarFileId:           req.AvatarFileID,
		PreferredContactMethod: ToProtoPreferredContactMethod(req.PreferredContactMethod),
	})
	profileResponse(c, http.StatusCreated, err, &models.UserProfileResponse{UserProfile: FromProtoUserProfile(res.GetUserProfile())})
}

func (ph *ProfileHandler) GetUserProfileByID(c *gin.Context) {
	var req models.GetUserProfileByIDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.GetUserProfileByID(profileRequestContext(c), &profilev1.GetUserProfileByIDRequest{Id: req.ID})
	profileResponse(c, http.StatusOK, err, &models.UserProfileResponse{UserProfile: FromProtoUserProfile(res.GetUserProfile())})
}

func (ph *ProfileHandler) GetUserProfileByUserID(c *gin.Context) {
	var req models.GetUserProfileByUserIDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.GetUserProfileByUserID(profileRequestContext(c), &profilev1.GetUserProfileByUserIDRequest{UserId: req.UserID})
	profileResponse(c, http.StatusOK, err, &models.UserProfileResponse{UserProfile: FromProtoUserProfile(res.GetUserProfile())})
}

func (ph *ProfileHandler) GetMyUserProfile(c *gin.Context) {
	res, err := ph.profileClient.GetMyUserProfile(profileRequestContext(c), &profilev1.GetMyUserProfileRequest{})
	profileResponse(c, http.StatusOK, err, &models.UserProfileResponse{UserProfile: FromProtoUserProfile(res.GetUserProfile())})
}

func (ph *ProfileHandler) ListUserProfiles(c *gin.Context) {
	var req models.ListUserProfilesRequest
	if !bindJSON(c, &req) {
		return
	}

	protoReq := &profilev1.ListUserProfilesRequest{
		Query:  req.Query,
		Limit:  int32OrZero(req.Limit),
		Offset: int32OrZero(req.Offset),
	}
	if req.SortBy != nil {
		sortBy := ToProtoUserProfileSortBy(*req.SortBy)
		protoReq.SortBy = &sortBy
	}
	if req.SortOrder != nil {
		sortOrder := ToProtoProfileSortOrder(*req.SortOrder)
		protoReq.SortOrder = &sortOrder
	}

	res, err := ph.profileClient.ListUserProfiles(profileRequestContext(c), protoReq)
	profileResponse(c, http.StatusOK, err, &models.ListUserProfilesResponse{
		UserProfiles: FromProtoUserProfiles(res.GetUserProfiles()),
		Total:        res.GetTotal(),
	})
}

func (ph *ProfileHandler) UpdateUserProfile(c *gin.Context) {
	var req models.UpdateUserProfileRequest
	if !bindJSON(c, &req) {
		return
	}

	protoReq := &profilev1.UpdateUserProfileRequest{
		Id:                req.ID,
		FullName:          req.FullName,
		Phone:             req.Phone,
		ClearPhone:        req.ClearPhone,
		AvatarFileId:      req.AvatarFileID,
		ClearAvatarFileId: req.ClearAvatarFileID,
	}
	if req.PreferredContactMethod != nil {
		contactMethod := ToProtoPreferredContactMethod(*req.PreferredContactMethod)
		protoReq.PreferredContactMethod = &contactMethod
	}

	res, err := ph.profileClient.UpdateUserProfile(profileRequestContext(c), protoReq)
	profileResponse(c, http.StatusOK, err, &models.UserProfileResponse{UserProfile: FromProtoUserProfile(res.GetUserProfile())})
}

func (ph *ProfileHandler) CreateWorkProfile(c *gin.Context) {
	var req models.CreateWorkProfileRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.CreateWorkProfile(profileRequestContext(c), &profilev1.CreateWorkProfileRequest{
		UserProfileId:  req.UserProfileID,
		DepartmentId:   req.DepartmentID,
		EmployeeNumber: req.EmployeeNumber,
		Position:       req.Position,
	})
	profileResponse(c, http.StatusCreated, err, &models.WorkProfileDetailsResponse{Details: FromProtoWorkProfileDetails(res.GetDetails())})
}

func (ph *ProfileHandler) GetWorkProfileByID(c *gin.Context) {
	var req models.GetWorkProfileByIDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.GetWorkProfileByID(profileRequestContext(c), &profilev1.GetWorkProfileByIDRequest{Id: req.ID})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileDetailsResponse{Details: FromProtoWorkProfileDetails(res.GetDetails())})
}

func (ph *ProfileHandler) GetWorkProfileByUserID(c *gin.Context) {
	var req models.GetWorkProfileByUserIDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.GetWorkProfileByUserID(profileRequestContext(c), &profilev1.GetWorkProfileByUserIDRequest{UserId: req.UserID})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileDetailsResponse{Details: FromProtoWorkProfileDetails(res.GetDetails())})
}

func (ph *ProfileHandler) ListWorkProfiles(c *gin.Context) {
	var req models.ListWorkProfilesRequest
	if !bindJSON(c, &req) {
		return
	}

	protoReq := &profilev1.ListWorkProfilesRequest{
		DepartmentId: req.DepartmentID,
		Query:        req.Query,
		Limit:        int32OrZero(req.Limit),
		Offset:       int32OrZero(req.Offset),
	}
	if req.Status != nil {
		status := ToProtoWorkProfileStatus(*req.Status)
		protoReq.Status = &status
	}
	if req.SortBy != nil {
		sortBy := ToProtoWorkProfileSortBy(*req.SortBy)
		protoReq.SortBy = &sortBy
	}
	if req.SortOrder != nil {
		sortOrder := ToProtoProfileSortOrder(*req.SortOrder)
		protoReq.SortOrder = &sortOrder
	}

	res, err := ph.profileClient.ListWorkProfiles(profileRequestContext(c), protoReq)
	profileResponse(c, http.StatusOK, err, &models.ListWorkProfilesResponse{
		WorkProfiles: FromProtoWorkProfileDetailsItems(res.GetWorkProfiles()),
		Total:        res.GetTotal(),
	})
}

func (ph *ProfileHandler) UpdateWorkProfile(c *gin.Context) {
	var req models.UpdateWorkProfileRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.UpdateWorkProfile(profileRequestContext(c), &profilev1.UpdateWorkProfileRequest{
		Id:                  req.ID,
		EmployeeNumber:      req.EmployeeNumber,
		ClearEmployeeNumber: req.ClearEmployeeNumber,
		Position:            req.Position,
	})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileDetailsResponse{Details: FromProtoWorkProfileDetails(res.GetDetails())})
}

func (ph *ProfileHandler) DeactivateWorkProfile(c *gin.Context) {
	var req models.DeactivateWorkProfileRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.DeactivateWorkProfile(profileRequestContext(c), &profilev1.DeactivateWorkProfileRequest{
		Id:     req.ID,
		Reason: req.Reason,
	})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileDetailsResponse{Details: FromProtoWorkProfileDetails(res.GetDetails())})
}

func (ph *ProfileHandler) ChangeWorkProfileDepartment(c *gin.Context) {
	var req models.ChangeWorkProfileDepartmentRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.ChangeWorkProfileDepartment(profileRequestContext(c), &profilev1.ChangeWorkProfileDepartmentRequest{
		Id:           req.ID,
		DepartmentId: req.DepartmentID,
		Reason:       req.Reason,
	})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileDetailsResponse{Details: FromProtoWorkProfileDetails(res.GetDetails())})
}

func (ph *ProfileHandler) SetWorkProfileStatus(c *gin.Context) {
	var req models.SetWorkProfileStatusRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.SetWorkProfileStatus(profileRequestContext(c), &profilev1.SetWorkProfileStatusRequest{
		Id:     req.ID,
		Status: ToProtoWorkProfileStatus(req.Status),
		Reason: req.Reason,
	})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileDetailsResponse{Details: FromProtoWorkProfileDetails(res.GetDetails())})
}

func (ph *ProfileHandler) GetWorkProfileStatusHistory(c *gin.Context) {
	var req models.WorkProfileStatusHistoryRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.GetWorkProfileStatusHistory(profileRequestContext(c), &profilev1.GetWorkProfileStatusHistoryRequest{
		WorkProfileId: req.WorkProfileID,
		Limit:         int32OrZero(req.Limit),
		Offset:        int32OrZero(req.Offset),
	})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileStatusHistoryResponse{
		History: FromProtoWorkProfileStatusHistoryItems(res.GetHistory()),
		Total:   res.GetTotal(),
	})
}

func (ph *ProfileHandler) ResolveWorkingDepartment(c *gin.Context) {
	var req models.ResolveWorkingDepartmentRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.ResolveWorkingDepartment(profileRequestContext(c), &profilev1.ResolveWorkingDepartmentRequest{UserId: req.UserID})
	profileResponse(c, http.StatusOK, err, &models.ResolveWorkingDepartmentResponse{
		UserProfileID:     res.GetUserProfileId(),
		WorkProfileID:     res.GetWorkProfileId(),
		UserID:            res.GetUserId(),
		DepartmentID:      res.GetDepartmentId(),
		WorkProfileStatus: FromProtoWorkProfileStatus(res.GetWorkProfileStatus()),
		CanOperate:        res.GetCanOperate(),
	})
}

func (ph *ProfileHandler) CheckProfileCanJoinBrigade(c *gin.Context) {
	var req models.CheckProfileCanJoinBrigadeRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.CheckProfileCanJoinBrigade(profileRequestContext(c), &profilev1.CheckProfileCanJoinBrigadeRequest{
		UserId:              req.UserID,
		WorkProfileId:       req.WorkProfileID,
		BrigadeDepartmentId: req.BrigadeDepartmentID,
	})
	profileResponse(c, http.StatusOK, err, &models.CheckProfileCanJoinBrigadeResponse{
		UserProfileID: res.GetUserProfileId(),
		WorkProfileID: res.GetWorkProfileId(),
		UserID:        res.GetUserId(),
		DepartmentID:  res.GetDepartmentId(),
		Allowed:       res.GetAllowed(),
		Reason:        FromProtoCanJoinBrigadeReason(res.GetReason()),
	})
}

func (ph *ProfileHandler) CreateCertificationType(c *gin.Context) {
	var req models.CreateCertificationTypeRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.CreateCertificationType(profileRequestContext(c), &profilev1.CreateCertificationTypeRequest{
		Code:                req.Code,
		Name:                req.Name,
		Description:         req.Description,
		DefaultValidityDays: req.DefaultValidityDays,
		RequiresFile:        req.RequiresFile,
	})
	profileResponse(c, http.StatusCreated, err, &models.CertificationTypeResponse{CertificationType: FromProtoCertificationType(res.GetCertificationType())})
}

func (ph *ProfileHandler) UpdateCertificationType(c *gin.Context) {
	var req models.UpdateCertificationTypeRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.UpdateCertificationType(profileRequestContext(c), &profilev1.UpdateCertificationTypeRequest{
		Id:                  req.ID,
		Code:                req.Code,
		Name:                req.Name,
		Description:         req.Description,
		ClearDescription:    req.ClearDescription,
		DefaultValidityDays: req.DefaultValidityDays,
		ClearValidityDays:   req.ClearValidityDays,
		RequiresFile:        req.RequiresFile,
		Active:              req.Active,
	})
	profileResponse(c, http.StatusOK, err, &models.CertificationTypeResponse{CertificationType: FromProtoCertificationType(res.GetCertificationType())})
}

func (ph *ProfileHandler) ListCertificationTypes(c *gin.Context) {
	var req models.ListCertificationTypesRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.ListCertificationTypes(profileRequestContext(c), &profilev1.ListCertificationTypesRequest{
		Active: req.Active,
		Query:  req.Query,
		Limit:  int32OrZero(req.Limit),
		Offset: int32OrZero(req.Offset),
	})
	profileResponse(c, http.StatusOK, err, &models.ListCertificationTypesResponse{
		CertificationTypes: FromProtoCertificationTypes(res.GetCertificationTypes()),
		Total:              res.GetTotal(),
	})
}

func (ph *ProfileHandler) AddCertificationTypeSkill(c *gin.Context) {
	var req models.CertificationTypeSkillRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.AddCertificationTypeSkill(profileRequestContext(c), &profilev1.AddCertificationTypeSkillRequest{
		CertificationTypeId: req.CertificationTypeID,
		SkillId:             req.SkillID,
		ProficiencyLevel:    req.ProficiencyLevel,
	})
	profileResponse(c, http.StatusCreated, err, &models.CertificationTypeSkillResponse{CertificationTypeSkill: FromProtoCertificationTypeSkill(res.GetCertificationTypeSkill())})
}

func (ph *ProfileHandler) RemoveCertificationTypeSkill(c *gin.Context) {
	var req models.CertificationTypeSkillRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.RemoveCertificationTypeSkill(profileRequestContext(c), &profilev1.RemoveCertificationTypeSkillRequest{
		CertificationTypeId: req.CertificationTypeID,
		SkillId:             req.SkillID,
	})
	profileResponse(c, http.StatusOK, err, &models.RemoveCertificationTypeSkillResponse{Success: res.GetSuccess()})
}

func (ph *ProfileHandler) ListCertificationTypeSkills(c *gin.Context) {
	var req models.ListCertificationTypeSkillsRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.ListCertificationTypeSkills(profileRequestContext(c), &profilev1.ListCertificationTypeSkillsRequest{
		CertificationTypeId: req.CertificationTypeID,
		ActiveOnly:          req.ActiveOnly,
	})
	profileResponse(c, http.StatusOK, err, &models.ListCertificationTypeSkillsResponse{Skills: FromProtoCertificationTypeSkills(res.GetSkills())})
}

func (ph *ProfileHandler) UploadWorkProfileCertification(c *gin.Context) {
	var req models.UploadWorkProfileCertificationRequest
	if !bindJSON(c, &req) {
		return
	}

	issuedAt, ok := ToOptionalProtoTimestamp(req.IssuedAt)
	if !ok {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid issued_at"})
		return
	}
	expiresAt, ok := ToOptionalProtoTimestamp(req.ExpiresAt)
	if !ok {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid expires_at"})
		return
	}

	res, err := ph.profileClient.UploadWorkProfileCertification(profileRequestContext(c), &profilev1.UploadWorkProfileCertificationRequest{
		WorkProfileId:       req.WorkProfileID,
		CertificationTypeId: req.CertificationTypeID,
		CertificateNumber:   req.CertificateNumber,
		Issuer:              req.Issuer,
		IssuedAt:            issuedAt,
		ExpiresAt:           expiresAt,
		CertificateFileId:   req.CertificateFileID,
	})
	profileResponse(c, http.StatusCreated, err, &models.WorkProfileCertificationResponse{Certification: FromProtoWorkProfileCertification(res.GetCertification())})
}

func (ph *ProfileHandler) VerifyWorkProfileCertification(c *gin.Context) {
	var req models.CertificationIDRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.VerifyWorkProfileCertification(profileRequestContext(c), &profilev1.VerifyWorkProfileCertificationRequest{Id: req.ID})
	profileResponse(c, http.StatusOK, err, &models.VerifyWorkProfileCertificationResponse{
		Certification: FromProtoWorkProfileCertification(res.GetCertification()),
		SkillGrants:   FromProtoWorkProfileSkillGrants(res.GetSkillGrants()),
	})
}

func (ph *ProfileHandler) RejectWorkProfileCertification(c *gin.Context) {
	var req models.RejectWorkProfileCertificationRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.RejectWorkProfileCertification(profileRequestContext(c), &profilev1.RejectWorkProfileCertificationRequest{
		Id:              req.ID,
		RejectionReason: req.RejectionReason,
	})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileCertificationResponse{Certification: FromProtoWorkProfileCertification(res.GetCertification())})
}

func (ph *ProfileHandler) RevokeWorkProfileCertification(c *gin.Context) {
	var req models.RevokeWorkProfileCertificationRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.RevokeWorkProfileCertification(profileRequestContext(c), &profilev1.RevokeWorkProfileCertificationRequest{
		Id:     req.ID,
		Reason: req.Reason,
	})
	profileResponse(c, http.StatusOK, err, &models.RevokeWorkProfileCertificationResponse{
		Certification: FromProtoWorkProfileCertification(res.GetCertification()),
		RevokedGrants: FromProtoWorkProfileSkillGrants(res.GetRevokedGrants()),
	})
}

func (ph *ProfileHandler) ExpireWorkProfileCertifications(c *gin.Context) {
	var req models.ExpireWorkProfileCertificationsRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.ExpireWorkProfileCertifications(profileRequestContext(c), &profilev1.ExpireWorkProfileCertificationsRequest{Limit: int32OrZero(req.Limit)})
	profileResponse(c, http.StatusOK, err, &models.ExpireWorkProfileCertificationsResponse{
		ExpiredCertifications: FromProtoWorkProfileCertifications(res.GetExpiredCertifications()),
		RevokedGrants:         FromProtoWorkProfileSkillGrants(res.GetRevokedGrants()),
	})
}

func (ph *ProfileHandler) ListWorkProfileCertifications(c *gin.Context) {
	var req models.ListWorkProfileCertificationsRequest
	if !bindJSON(c, &req) {
		return
	}

	protoReq := &profilev1.ListWorkProfileCertificationsRequest{
		WorkProfileId:       req.WorkProfileID,
		CertificationTypeId: req.CertificationTypeID,
		Limit:               int32OrZero(req.Limit),
		Offset:              int32OrZero(req.Offset),
	}
	if req.Status != nil {
		status := ToProtoCertificationStatus(*req.Status)
		protoReq.Status = &status
	}

	res, err := ph.profileClient.ListWorkProfileCertifications(profileRequestContext(c), protoReq)
	profileResponse(c, http.StatusOK, err, &models.ListWorkProfileCertificationsResponse{
		Certifications: FromProtoWorkProfileCertifications(res.GetCertifications()),
		Total:          res.GetTotal(),
	})
}

func (ph *ProfileHandler) GrantManualWorkProfileSkill(c *gin.Context) {
	var req models.GrantManualWorkProfileSkillRequest
	if !bindJSON(c, &req) {
		return
	}

	validUntil, ok := ToOptionalProtoTimestamp(req.ValidUntil)
	if !ok {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid valid_until"})
		return
	}

	res, err := ph.profileClient.GrantManualWorkProfileSkill(profileRequestContext(c), &profilev1.GrantManualWorkProfileSkillRequest{
		WorkProfileId:    req.WorkProfileID,
		SkillId:          req.SkillID,
		ProficiencyLevel: req.ProficiencyLevel,
		ValidUntil:       validUntil,
		Reason:           req.Reason,
	})
	profileResponse(c, http.StatusCreated, err, &models.WorkProfileSkillGrantResponse{SkillGrant: FromProtoWorkProfileSkillGrant(res.GetSkillGrant())})
}

func (ph *ProfileHandler) RevokeWorkProfileSkillGrant(c *gin.Context) {
	var req models.RevokeWorkProfileSkillGrantRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.RevokeWorkProfileSkillGrant(profileRequestContext(c), &profilev1.RevokeWorkProfileSkillGrantRequest{
		Id:     req.ID,
		Reason: req.Reason,
	})
	profileResponse(c, http.StatusOK, err, &models.WorkProfileSkillGrantResponse{SkillGrant: FromProtoWorkProfileSkillGrant(res.GetSkillGrant())})
}

func (ph *ProfileHandler) ListEffectiveWorkProfileSkills(c *gin.Context) {
	var req models.ListEffectiveWorkProfileSkillsRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.ListEffectiveWorkProfileSkills(profileRequestContext(c), &profilev1.ListEffectiveWorkProfileSkillsRequest{WorkProfileId: req.WorkProfileID})
	profileResponse(c, http.StatusOK, err, &models.ListEffectiveWorkProfileSkillsResponse{SkillGrants: FromProtoWorkProfileSkillGrants(res.GetSkillGrants())})
}

func (ph *ProfileHandler) BatchListEffectiveWorkProfileSkills(c *gin.Context) {
	var req models.BatchListEffectiveWorkProfileSkillsRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.BatchListEffectiveWorkProfileSkills(profileRequestContext(c), &profilev1.BatchListEffectiveWorkProfileSkillsRequest{WorkProfileIds: req.WorkProfileIDs})
	profileResponse(c, http.StatusOK, err, &models.BatchListEffectiveWorkProfileSkillsResponse{Items: FromProtoEffectiveWorkProfileSkillsItems(res.GetItems())})
}

func (ph *ProfileHandler) CheckWorkProfileHasSkills(c *gin.Context) {
	var req models.CheckWorkProfileHasSkillsRequest
	if !bindJSON(c, &req) {
		return
	}

	res, err := ph.profileClient.CheckWorkProfileHasSkills(profileRequestContext(c), &profilev1.CheckWorkProfileHasSkillsRequest{
		WorkProfileId:    req.WorkProfileID,
		RequiredSkillIds: req.RequiredSkillIDs,
	})
	profileResponse(c, http.StatusOK, err, &models.CheckWorkProfileHasSkillsResponse{
		Allowed:         res.GetAllowed(),
		MissingSkillIDs: res.GetMissingSkillIds(),
	})
}

func profileRequestContext(c *gin.Context) context.Context {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	c.Set("profile_cancel", cancel)
	return gatewayActorContext(ctx, c)
}

func profileResponse(c *gin.Context, httpStatus int, err error, response any) {
	if cancelValue, ok := c.Get("profile_cancel"); ok {
		if cancel, ok := cancelValue.(context.CancelFunc); ok {
			defer cancel()
		}
	}
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	c.JSON(httpStatus, response)
}
