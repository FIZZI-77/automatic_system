package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"profile/models"
	"profile/src/core/service"
)

type mockProfileService struct {
	createUserProfileFunc                   func(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error)
	getUserProfileByIDFunc                  func(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error)
	listWorkProfilesFunc                    func(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error)
	verifyWorkProfileCertificationFunc      func(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error)
	batchListEffectiveWorkProfileSkillsFunc func(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error)
	checkWorkProfileHasSkillsFunc           func(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error)
}

func (m *mockProfileService) CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
	return m.createUserProfileFunc(ctx, in)
}
func (m *mockProfileService) GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error) {
	return m.getUserProfileByIDFunc(ctx, in)
}
func (m *mockProfileService) GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error) {
	return nil, nil
}
func (m *mockProfileService) GetMyUserProfile(ctx context.Context, in *models.GetMyUserProfileInput) (*models.GetMyUserProfileResult, error) {
	return nil, nil
}
func (m *mockProfileService) ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error) {
	return nil, nil
}
func (m *mockProfileService) UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error) {
	return nil, nil
}
func (m *mockProfileService) CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error) {
	return nil, nil
}
func (m *mockProfileService) GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error) {
	return nil, nil
}
func (m *mockProfileService) GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error) {
	return nil, nil
}
func (m *mockProfileService) ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error) {
	return m.listWorkProfilesFunc(ctx, in)
}
func (m *mockProfileService) UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error) {
	return nil, nil
}
func (m *mockProfileService) DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error) {
	return nil, nil
}
func (m *mockProfileService) ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error) {
	return nil, nil
}
func (m *mockProfileService) SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error) {
	return nil, nil
}
func (m *mockProfileService) GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error) {
	return nil, nil
}
func (m *mockProfileService) ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error) {
	return nil, nil
}
func (m *mockProfileService) CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error) {
	return nil, nil
}
func (m *mockProfileService) CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error) {
	return nil, nil
}
func (m *mockProfileService) UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error) {
	return nil, nil
}
func (m *mockProfileService) ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error) {
	return nil, nil
}
func (m *mockProfileService) AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error) {
	return nil, nil
}
func (m *mockProfileService) RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error {
	return nil
}
func (m *mockProfileService) ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error) {
	return nil, nil
}
func (m *mockProfileService) UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error) {
	return nil, nil
}
func (m *mockProfileService) VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error) {
	return m.verifyWorkProfileCertificationFunc(ctx, in)
}
func (m *mockProfileService) RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error) {
	return nil, nil
}
func (m *mockProfileService) RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error) {
	return nil, nil
}
func (m *mockProfileService) ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error) {
	return nil, nil
}
func (m *mockProfileService) ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error) {
	return nil, nil
}
func (m *mockProfileService) GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error) {
	return nil, nil
}
func (m *mockProfileService) RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error) {
	return nil, nil
}
func (m *mockProfileService) ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error) {
	return nil, nil
}
func (m *mockProfileService) BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error) {
	return m.batchListEffectiveWorkProfileSkillsFunc(ctx, in)
}
func (m *mockProfileService) CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error) {
	return m.checkWorkProfileHasSkillsFunc(ctx, in)
}

func newTestProfileHandler(mock *mockProfileService) *ProfileHandler {
	return NewProfileHandler(&service.Service{
		UserProfileService:     mock,
		WorkProfileService:     mock,
		ProfileInternalService: mock,
		CertificationService:   mock,
	}, zap.NewNop())
}

func profileHandlerContext(userID uuid.UUID, roles string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-actor-user-id", userID.String(),
		"x-actor-roles", roles,
		"x-request-id", "request-1",
		"x-trace-id", "trace-1",
	))
}

func assertProfileGRPCCode(t *testing.T, err error, expected codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}
	if st.Code() != expected {
		t.Fatalf("expected grpc code %v, got %v", expected, st.Code())
	}
}

func testHandlerUserProfile(profileID uuid.UUID, userID uuid.UUID) *models.UserProfile {
	return &models.UserProfile{
		ID:                     profileID,
		UserID:                 userID,
		FullName:               "Ivan Ivanov",
		PreferredContactMethod: models.PreferredContactMethodEmail,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
}

func TestProfileHandler_CreateUserProfile_Success(t *testing.T) {
	userID := uuid.New()
	profileID := uuid.New()
	phone := "+79991234567"
	mock := &mockProfileService{
		createUserProfileFunc: func(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
			if in.UserID != userID {
				t.Fatalf("expected user id %s, got %s", userID, in.UserID)
			}
			if in.ActorUserID == nil || *in.ActorUserID != userID {
				t.Fatalf("expected actor user id %s, got %v", userID, in.ActorUserID)
			}
			if len(in.ActorRoles) != 2 {
				t.Fatalf("expected two actor roles, got %#v", in.ActorRoles)
			}
			if in.Phone == nil || *in.Phone != phone {
				t.Fatalf("expected phone %s, got %v", phone, in.Phone)
			}
			if in.PreferredContactMethod != models.PreferredContactMethodPhone {
				t.Fatalf("expected PHONE contact method, got %s", in.PreferredContactMethod)
			}
			profile := testHandlerUserProfile(profileID, userID)
			profile.Phone = &phone
			profile.PreferredContactMethod = models.PreferredContactMethodPhone
			return &models.CreateUserProfileResult{UserProfile: profile}, nil
		},
	}
	h := newTestProfileHandler(mock)

	resp, err := h.CreateUserProfile(profileHandlerContext(userID, "admin,hr"), &profilev1.CreateUserProfileRequest{
		UserId:                 userID.String(),
		FullName:               "Ivan Ivanov",
		Phone:                  &phone,
		PreferredContactMethod: profilev1.PreferredContactMethod_PREFERRED_CONTACT_METHOD_PHONE,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetUserProfile().GetId() != profileID.String() {
		t.Fatalf("expected profile id %s, got %s", profileID, resp.GetUserProfile().GetId())
	}
	if resp.GetUserProfile().GetPhone() != phone {
		t.Fatalf("expected phone %s, got %s", phone, resp.GetUserProfile().GetPhone())
	}
}

func TestProfileHandler_CreateUserProfile_InvalidUserID(t *testing.T) {
	h := newTestProfileHandler(&mockProfileService{})

	resp, err := h.CreateUserProfile(context.Background(), &profilev1.CreateUserProfileRequest{
		UserId:   "bad-id",
		FullName: "Ivan Ivanov",
	})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertProfileGRPCCode(t, err, codes.InvalidArgument)
}

func TestProfileHandler_GetUserProfileByID_MapsNotFound(t *testing.T) {
	profileID := uuid.New()
	h := newTestProfileHandler(&mockProfileService{
		getUserProfileByIDFunc: func(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error) {
			return nil, models.ErrNotFound
		},
	})

	resp, err := h.GetUserProfileByID(context.Background(), &profilev1.GetUserProfileByIDRequest{Id: profileID.String()})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertProfileGRPCCode(t, err, codes.NotFound)
}

func TestProfileHandler_ListWorkProfiles_ParsesOptionalFilters(t *testing.T) {
	departmentID := uuid.New()
	statusFilter := profilev1.WorkProfileStatus_WORK_PROFILE_STATUS_ACTIVE
	sortBy := profilev1.WorkProfileSortBy_WORK_PROFILE_SORT_BY_FULL_NAME
	sortOrder := profilev1.SortOrder_SORT_ORDER_ASC
	mock := &mockProfileService{
		listWorkProfilesFunc: func(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error) {
			if in.DepartmentID == nil || *in.DepartmentID != departmentID {
				t.Fatalf("expected department id %s, got %v", departmentID, in.DepartmentID)
			}
			if in.Status == nil || *in.Status != models.WorkProfileStatusActive {
				t.Fatalf("expected status ACTIVE, got %v", in.Status)
			}
			if in.SortBy != models.WorkProfileSortByFullName || in.SortOrder != models.SortOrderAsc {
				t.Fatalf("unexpected sorting: %s %s", in.SortBy, in.SortOrder)
			}
			return &models.ListWorkProfilesResult{WorkProfiles: []*models.WorkProfileDetails{}, Total: 0}, nil
		},
	}
	h := newTestProfileHandler(mock)

	resp, err := h.ListWorkProfiles(context.Background(), &profilev1.ListWorkProfilesRequest{
		DepartmentId: &[]string{departmentID.String()}[0],
		Status:       &statusFilter,
		Limit:        10,
		Offset:       5,
		SortBy:       &sortBy,
		SortOrder:    &sortOrder,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetTotal() != 0 {
		t.Fatalf("expected total 0, got %d", resp.GetTotal())
	}
}

func TestProfileHandler_VerifyCertification_ReturnsSkillGrants(t *testing.T) {
	certificationID := uuid.New()
	workProfileID := uuid.New()
	skillID := uuid.New()
	grantID := uuid.New()
	h := newTestProfileHandler(&mockProfileService{
		verifyWorkProfileCertificationFunc: func(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error) {
			return &models.VerifyWorkProfileCertificationResult{
				Certification: &models.WorkProfileCertification{
					ID:            certificationID,
					WorkProfileID: workProfileID,
					Status:        models.CertificationStatusVerified,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				},
				SkillGrants: []*models.WorkProfileSkillGrant{
					{
						ID:            grantID,
						WorkProfileID: workProfileID,
						SkillID:       skillID,
						SourceType:    models.SkillGrantSourceTypeCertification,
						Active:        true,
						CreatedAt:     time.Now(),
					},
				},
			}, nil
		},
	})

	resp, err := h.VerifyWorkProfileCertification(context.Background(), &profilev1.VerifyWorkProfileCertificationRequest{Id: certificationID.String()})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(resp.GetSkillGrants()) != 1 || resp.GetSkillGrants()[0].GetSkillId() != skillID.String() {
		t.Fatalf("unexpected skill grants: %+v", resp.GetSkillGrants())
	}
}

func TestProfileErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "validation", err: models.ErrValidation, code: codes.InvalidArgument},
		{name: "not found", err: models.ErrNotFound, code: codes.NotFound},
		{name: "permission", err: models.ErrPermissionDenied, code: codes.PermissionDenied},
		{name: "idempotency processing", err: models.ErrIdempotencyInProgress, code: codes.Aborted},
		{name: "failed precondition", err: models.ErrWorkProfileInactive, code: codes.FailedPrecondition},
		{name: "wrapped", err: errors.New("plain error"), code: codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := profileErrorCode(tt.err); got != tt.code {
				t.Fatalf("expected %v, got %v", tt.code, got)
			}
		})
	}
}
