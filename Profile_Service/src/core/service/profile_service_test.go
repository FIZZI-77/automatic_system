package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"profile/models"
	"profile/src/core/repository"
)

type mockProfileRepo struct {
	createUserProfileFunc                   func(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error)
	updateUserProfileFunc                   func(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error)
	getUserProfileByIDFunc                  func(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error)
	getUserProfileByUserIDFunc              func(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error)
	listUserProfilesFunc                    func(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error)
	createWorkProfileFunc                   func(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error)
	updateWorkProfileFunc                   func(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error)
	getWorkProfileByIDFunc                  func(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error)
	getWorkProfileByUserIDFunc              func(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error)
	listWorkProfilesFunc                    func(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error)
	deactivateWorkProfileFunc               func(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error)
	changeWorkProfileDepartmentFunc         func(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error)
	setWorkProfileStatusFunc                func(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error)
	getWorkProfileStatusHistoryFunc         func(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error)
	resolveWorkingDepartmentFunc            func(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error)
	checkProfileCanJoinBrigadeFunc          func(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error)
	createCertificationTypeFunc             func(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error)
	updateCertificationTypeFunc             func(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error)
	getCertificationTypeByIDFunc            func(ctx context.Context, id uuid.UUID) (*models.CertificationType, error)
	listCertificationTypesFunc              func(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error)
	addCertificationTypeSkillFunc           func(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error)
	removeCertificationTypeSkillFunc        func(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error
	listCertificationTypeSkillsFunc         func(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error)
	uploadWorkProfileCertificationFunc      func(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error)
	verifyWorkProfileCertificationFunc      func(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error)
	rejectWorkProfileCertificationFunc      func(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error)
	revokeWorkProfileCertificationFunc      func(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error)
	expireWorkProfileCertificationsFunc     func(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error)
	listWorkProfileCertificationsFunc       func(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error)
	grantManualWorkProfileSkillFunc         func(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error)
	revokeWorkProfileSkillGrantFunc         func(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error)
	listEffectiveWorkProfileSkillsFunc      func(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error)
	batchListEffectiveWorkProfileSkillsFunc func(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error)
	checkWorkProfileHasSkillsFunc           func(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error)
}

func (m *mockProfileRepo) CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
	return m.createUserProfileFunc(ctx, in)
}
func (m *mockProfileRepo) UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error) {
	return m.updateUserProfileFunc(ctx, in)
}
func (m *mockProfileRepo) GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error) {
	return m.getUserProfileByIDFunc(ctx, in)
}
func (m *mockProfileRepo) GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error) {
	return m.getUserProfileByUserIDFunc(ctx, in)
}
func (m *mockProfileRepo) ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error) {
	return m.listUserProfilesFunc(ctx, in)
}
func (m *mockProfileRepo) CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error) {
	return m.createWorkProfileFunc(ctx, in)
}
func (m *mockProfileRepo) UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error) {
	return m.updateWorkProfileFunc(ctx, in)
}
func (m *mockProfileRepo) GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error) {
	return m.getWorkProfileByIDFunc(ctx, in)
}
func (m *mockProfileRepo) GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error) {
	return m.getWorkProfileByUserIDFunc(ctx, in)
}
func (m *mockProfileRepo) ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error) {
	return m.listWorkProfilesFunc(ctx, in)
}
func (m *mockProfileRepo) DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error) {
	return m.deactivateWorkProfileFunc(ctx, in)
}
func (m *mockProfileRepo) ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error) {
	return m.changeWorkProfileDepartmentFunc(ctx, in)
}
func (m *mockProfileRepo) SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error) {
	return m.setWorkProfileStatusFunc(ctx, in)
}
func (m *mockProfileRepo) GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error) {
	return m.getWorkProfileStatusHistoryFunc(ctx, in)
}
func (m *mockProfileRepo) ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error) {
	return m.resolveWorkingDepartmentFunc(ctx, in)
}
func (m *mockProfileRepo) CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error) {
	return m.checkProfileCanJoinBrigadeFunc(ctx, in)
}
func (m *mockProfileRepo) CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error) {
	return m.createCertificationTypeFunc(ctx, in)
}
func (m *mockProfileRepo) UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error) {
	return m.updateCertificationTypeFunc(ctx, in)
}
func (m *mockProfileRepo) GetCertificationTypeByID(ctx context.Context, id uuid.UUID) (*models.CertificationType, error) {
	return m.getCertificationTypeByIDFunc(ctx, id)
}
func (m *mockProfileRepo) ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error) {
	return m.listCertificationTypesFunc(ctx, in)
}
func (m *mockProfileRepo) AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error) {
	return m.addCertificationTypeSkillFunc(ctx, in)
}
func (m *mockProfileRepo) RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error {
	return m.removeCertificationTypeSkillFunc(ctx, in)
}
func (m *mockProfileRepo) ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error) {
	return m.listCertificationTypeSkillsFunc(ctx, in)
}
func (m *mockProfileRepo) UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error) {
	return m.uploadWorkProfileCertificationFunc(ctx, in)
}
func (m *mockProfileRepo) VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error) {
	return m.verifyWorkProfileCertificationFunc(ctx, in)
}
func (m *mockProfileRepo) RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error) {
	return m.rejectWorkProfileCertificationFunc(ctx, in)
}
func (m *mockProfileRepo) RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error) {
	return m.revokeWorkProfileCertificationFunc(ctx, in)
}
func (m *mockProfileRepo) ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error) {
	return m.expireWorkProfileCertificationsFunc(ctx, in)
}
func (m *mockProfileRepo) ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error) {
	return m.listWorkProfileCertificationsFunc(ctx, in)
}
func (m *mockProfileRepo) GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error) {
	return m.grantManualWorkProfileSkillFunc(ctx, in)
}
func (m *mockProfileRepo) RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error) {
	return m.revokeWorkProfileSkillGrantFunc(ctx, in)
}
func (m *mockProfileRepo) ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error) {
	return m.listEffectiveWorkProfileSkillsFunc(ctx, in)
}
func (m *mockProfileRepo) BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error) {
	return m.batchListEffectiveWorkProfileSkillsFunc(ctx, in)
}
func (m *mockProfileRepo) CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error) {
	return m.checkWorkProfileHasSkillsFunc(ctx, in)
}

type mockUserChecker struct {
	ensureFunc func(ctx context.Context, userID uuid.UUID) error
}

func (m *mockUserChecker) EnsureUserExists(ctx context.Context, userID uuid.UUID) error {
	return m.ensureFunc(ctx, userID)
}

type mockDepartmentChecker struct {
	ensureFunc func(ctx context.Context, departmentID uuid.UUID) error
}

func (m *mockDepartmentChecker) EnsureDepartmentActive(ctx context.Context, departmentID uuid.UUID) error {
	return m.ensureFunc(ctx, departmentID)
}

func newTestServiceRepo(mock *mockProfileRepo) *repository.Repository {
	return &repository.Repository{
		UserProfileRepository:   mock,
		WorkProfileRepository:   mock,
		CertificationRepository: mock,
	}
}

func testUserProfile(id uuid.UUID, userID uuid.UUID) *models.UserProfile {
	return &models.UserProfile{
		ID:                     id,
		UserID:                 userID,
		FullName:               "Ivan Ivanov",
		PreferredContactMethod: models.PreferredContactMethodEmail,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
}

func testWorkProfileDetails(workProfileID uuid.UUID, userProfileID uuid.UUID, userID uuid.UUID, departmentID uuid.UUID, status models.WorkProfileStatus) *models.WorkProfileDetails {
	return &models.WorkProfileDetails{
		WorkProfile: &models.WorkProfile{
			ID:            workProfileID,
			UserProfileID: userProfileID,
			DepartmentID:  departmentID,
			Position:      "Engineer",
			Status:        status,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		UserProfile: testUserProfile(userProfileID, userID),
	}
}

func assertProfileErrorIs(t *testing.T, err error, expected error) {
	t.Helper()
	if !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}

func TestUserProfileService_CreateUserProfile_Success(t *testing.T) {
	userID := uuid.New()
	profileID := uuid.New()
	userChecked := false
	repoCalled := false

	svc := NewUserProfileServiceStruct(newTestServiceRepo(&mockProfileRepo{
		createUserProfileFunc: func(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
			repoCalled = true
			if in.UserID != userID {
				t.Fatalf("expected user id %s, got %s", userID, in.UserID)
			}
			return &models.CreateUserProfileResult{UserProfile: testUserProfile(profileID, userID)}, nil
		},
	}), &mockUserChecker{ensureFunc: func(ctx context.Context, id uuid.UUID) error {
		userChecked = true
		if id != userID {
			t.Fatalf("expected checked user id %s, got %s", userID, id)
		}
		return nil
	}}, zap.NewNop())

	result, err := svc.CreateUserProfile(context.Background(), &models.CreateUserProfileInput{
		UserID:      userID,
		FullName:    "Ivan Ivanov",
		ActorUserID: &userID,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if userChecked {
		t.Fatal("self profile creation should not call auth user checker")
	}
	if !repoCalled {
		t.Fatal("expected profile repository to be called")
	}
	if result.UserProfile.ID != profileID {
		t.Fatalf("expected profile id %s, got %s", profileID, result.UserProfile.ID)
	}
}

func TestUserProfileService_CreateUserProfile_AdminChecksTargetUser(t *testing.T) {
	userID := uuid.New()
	adminID := uuid.New()
	profileID := uuid.New()
	userChecked := false

	svc := NewUserProfileServiceStruct(newTestServiceRepo(&mockProfileRepo{
		createUserProfileFunc: func(context.Context, *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
			return &models.CreateUserProfileResult{UserProfile: testUserProfile(profileID, userID)}, nil
		},
	}), &mockUserChecker{ensureFunc: func(_ context.Context, id uuid.UUID) error {
		userChecked = true
		if id != userID {
			t.Fatalf("EnsureUserExists(%s) checked user ID = %s, want %s", userID, id, userID)
		}
		return nil
	}}, zap.NewNop())

	result, err := svc.CreateUserProfile(context.Background(), &models.CreateUserProfileInput{
		UserID:      userID,
		FullName:    "Ivan Ivanov",
		ActorUserID: &adminID,
		ActorRoles:  []string{"admin"},
	})
	if err != nil {
		t.Fatalf("CreateUserProfile(admin, %s) error = %v, want nil", userID, err)
	}
	if result == nil || result.UserProfile.ID != profileID {
		t.Fatalf("CreateUserProfile(admin, %s) result = %#v, want profile %s", userID, result, profileID)
	}
	if !userChecked {
		t.Fatal("admin profile creation should check that target auth user exists")
	}
}

func TestUserProfileService_CreateUserProfile_PermissionDenied(t *testing.T) {
	userID := uuid.New()
	actorID := uuid.New()
	repoCalled := false

	svc := NewUserProfileServiceStruct(newTestServiceRepo(&mockProfileRepo{
		createUserProfileFunc: func(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
			repoCalled = true
			return nil, nil
		},
	}), nil, zap.NewNop())

	result, err := svc.CreateUserProfile(context.Background(), &models.CreateUserProfileInput{
		UserID:      userID,
		FullName:    "Ivan Ivanov",
		ActorUserID: &actorID,
		ActorRoles:  []string{"operator"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	assertProfileErrorIs(t, err, models.ErrPermissionDenied)
	if repoCalled {
		t.Fatal("repo should not be called")
	}
}

func TestUserProfileService_GetUserProfileByID_DeniesOtherUser(t *testing.T) {
	profileOwnerID := uuid.New()
	actorID := uuid.New()
	profileID := uuid.New()

	svc := NewUserProfileServiceStruct(newTestServiceRepo(&mockProfileRepo{
		getUserProfileByIDFunc: func(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error) {
			return &models.GetUserProfileByIDResult{UserProfile: testUserProfile(profileID, profileOwnerID)}, nil
		},
	}), nil, zap.NewNop())

	result, err := svc.GetUserProfileByID(context.Background(), &models.GetUserProfileByIDInput{
		ID:          profileID,
		ActorUserID: &actorID,
		ActorRoles:  []string{"worker"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	assertProfileErrorIs(t, err, models.ErrPermissionDenied)
}

func TestWorkProfileService_CreateWorkProfile_Success(t *testing.T) {
	userID := uuid.New()
	userProfileID := uuid.New()
	workProfileID := uuid.New()
	departmentID := uuid.New()
	departmentChecked := false

	svc := NewWorkProfileServiceStruct(newTestServiceRepo(&mockProfileRepo{
		getUserProfileByIDFunc: func(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error) {
			if in.ID != userProfileID {
				t.Fatalf("expected user profile id %s, got %s", userProfileID, in.ID)
			}
			return &models.GetUserProfileByIDResult{UserProfile: testUserProfile(userProfileID, userID)}, nil
		},
		createWorkProfileFunc: func(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error) {
			return &models.CreateWorkProfileResult{Details: testWorkProfileDetails(workProfileID, userProfileID, userID, departmentID, models.WorkProfileStatusActive)}, nil
		},
	}), &mockDepartmentChecker{ensureFunc: func(ctx context.Context, id uuid.UUID) error {
		departmentChecked = true
		if id != departmentID {
			t.Fatalf("expected department id %s, got %s", departmentID, id)
		}
		return nil
	}}, zap.NewNop())

	result, err := svc.CreateWorkProfile(context.Background(), &models.CreateWorkProfileInput{
		UserProfileID: userProfileID,
		DepartmentID:  departmentID,
		Position:      "Engineer",
		ActorRoles:    []string{"admin"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !departmentChecked {
		t.Fatal("expected department checker to be called")
	}
	if result.Details.WorkProfile.ID != workProfileID {
		t.Fatalf("expected work profile id %s, got %s", workProfileID, result.Details.WorkProfile.ID)
	}
}

func TestWorkProfileService_ListWorkProfiles_DispatcherScopedToOwnDepartment(t *testing.T) {
	dispatcherID := uuid.New()
	departmentID := uuid.New()

	svc := NewWorkProfileServiceStruct(newTestServiceRepo(&mockProfileRepo{
		resolveWorkingDepartmentFunc: func(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error) {
			if in.UserID != dispatcherID {
				t.Fatalf("expected dispatcher id %s, got %s", dispatcherID, in.UserID)
			}
			return &models.ResolveWorkingDepartmentResult{DepartmentID: departmentID, CanOperate: true}, nil
		},
		listWorkProfilesFunc: func(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error) {
			if in.DepartmentID == nil || *in.DepartmentID != departmentID {
				t.Fatalf("expected department to be scoped to %s, got %v", departmentID, in.DepartmentID)
			}
			if in.Limit != models.DefaultLimit || in.Offset != 0 {
				t.Fatalf("expected normalized pagination, got limit=%d offset=%d", in.Limit, in.Offset)
			}
			return &models.ListWorkProfilesResult{WorkProfiles: []*models.WorkProfileDetails{}, Total: 0}, nil
		},
	}), nil, zap.NewNop())

	result, err := svc.ListWorkProfiles(context.Background(), &models.ListWorkProfilesInput{
		ActorUserID: &dispatcherID,
		ActorRoles:  []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Total != 0 {
		t.Fatalf("expected total 0, got %d", result.Total)
	}
}

func TestWorkProfileService_SetWorkProfileStatus_WorkerTransitionRules(t *testing.T) {
	userID := uuid.New()
	userProfileID := uuid.New()
	workProfileID := uuid.New()
	departmentID := uuid.New()
	setCalled := false

	svc := NewWorkProfileServiceStruct(newTestServiceRepo(&mockProfileRepo{
		getWorkProfileByIDFunc: func(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error) {
			return &models.GetWorkProfileByIDResult{
				Details: testWorkProfileDetails(workProfileID, userProfileID, userID, departmentID, models.WorkProfileStatusActive),
			}, nil
		},
		setWorkProfileStatusFunc: func(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error) {
			setCalled = true
			if in.Status != models.WorkProfileStatusOnShift {
				t.Fatalf("expected status ON_SHIFT, got %s", in.Status)
			}
			return &models.SetWorkProfileStatusResult{
				Details: testWorkProfileDetails(workProfileID, userProfileID, userID, departmentID, models.WorkProfileStatusOnShift),
			}, nil
		},
	}), nil, zap.NewNop())

	result, err := svc.SetWorkProfileStatus(context.Background(), &models.SetWorkProfileStatusInput{
		ID:          workProfileID,
		Status:      models.WorkProfileStatusOnShift,
		Reason:      "start shift",
		ActorUserID: &userID,
		ActorRoles:  []string{"worker"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !setCalled {
		t.Fatal("expected repo SetWorkProfileStatus to be called")
	}
	if result.Details.WorkProfile.Status != models.WorkProfileStatusOnShift {
		t.Fatalf("expected status ON_SHIFT, got %s", result.Details.WorkProfile.Status)
	}

	_, err = svc.SetWorkProfileStatus(context.Background(), &models.SetWorkProfileStatusInput{
		ID:          workProfileID,
		Status:      models.WorkProfileStatusSuspended,
		Reason:      "bad transition",
		ActorUserID: &userID,
		ActorRoles:  []string{"worker"},
	})
	assertProfileErrorIs(t, err, models.ErrInvalidStatus)
}

func TestCertificationService_UploadWorkProfileCertification_Success(t *testing.T) {
	userID := uuid.New()
	userProfileID := uuid.New()
	workProfileID := uuid.New()
	departmentID := uuid.New()
	certificationTypeID := uuid.New()
	certificationID := uuid.New()
	fileID := uuid.New()

	svc := NewCertificationServiceStruct(newTestServiceRepo(&mockProfileRepo{
		getCertificationTypeByIDFunc: func(ctx context.Context, id uuid.UUID) (*models.CertificationType, error) {
			if id != certificationTypeID {
				t.Fatalf("expected certification type id %s, got %s", certificationTypeID, id)
			}
			return &models.CertificationType{
				ID:           certificationTypeID,
				Code:         "ELECTRICIAN",
				Name:         "Electrician",
				RequiresFile: true,
				Active:       true,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}, nil
		},
		getWorkProfileByIDFunc: func(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error) {
			return &models.GetWorkProfileByIDResult{
				Details: testWorkProfileDetails(workProfileID, userProfileID, userID, departmentID, models.WorkProfileStatusActive),
			}, nil
		},
		uploadWorkProfileCertificationFunc: func(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error) {
			if in.CertificateFileID == nil || *in.CertificateFileID != fileID {
				t.Fatalf("expected certificate file id %s, got %v", fileID, in.CertificateFileID)
			}
			return &models.UploadWorkProfileCertificationResult{
				Certification: &models.WorkProfileCertification{
					ID:                  certificationID,
					WorkProfileID:       workProfileID,
					CertificationTypeID: certificationTypeID,
					Status:              models.CertificationStatusPending,
					CertificateFileID:   &fileID,
					CreatedAt:           time.Now(),
					UpdatedAt:           time.Now(),
				},
			}, nil
		},
	}), zap.NewNop())

	result, err := svc.UploadWorkProfileCertification(context.Background(), &models.UploadWorkProfileCertificationInput{
		WorkProfileID:       workProfileID,
		CertificationTypeID: certificationTypeID,
		CertificateFileID:   &fileID,
		ActorUserID:         &userID,
		ActorRoles:          []string{"worker"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Certification.ID != certificationID {
		t.Fatalf("expected certification id %s, got %s", certificationID, result.Certification.ID)
	}
}

func TestCertificationService_VerifyWorkProfileCertification_HRAllowed(t *testing.T) {
	certificationID := uuid.New()
	actorID := uuid.New()
	skillGrantID := uuid.New()

	svc := NewCertificationServiceStruct(newTestServiceRepo(&mockProfileRepo{
		verifyWorkProfileCertificationFunc: func(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error) {
			if in.ID != certificationID {
				t.Fatalf("expected certification id %s, got %s", certificationID, in.ID)
			}
			return &models.VerifyWorkProfileCertificationResult{
				Certification: &models.WorkProfileCertification{ID: certificationID, Status: models.CertificationStatusVerified},
				SkillGrants: []*models.WorkProfileSkillGrant{
					{ID: skillGrantID, SourceType: models.SkillGrantSourceTypeCertification, Active: true},
				},
			}, nil
		},
	}), zap.NewNop())

	result, err := svc.VerifyWorkProfileCertification(context.Background(), &models.VerifyWorkProfileCertificationInput{
		ID:          certificationID,
		ActorUserID: &actorID,
		ActorRoles:  []string{"qualification_verifier"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result.SkillGrants) != 1 || result.SkillGrants[0].ID != skillGrantID {
		t.Fatalf("unexpected skill grants: %+v", result.SkillGrants)
	}
}

func TestCertificationService_BatchListEffectiveSkills_InternalAllowed(t *testing.T) {
	workProfileID := uuid.New()
	skillID := uuid.New()

	svc := NewCertificationServiceStruct(newTestServiceRepo(&mockProfileRepo{
		batchListEffectiveWorkProfileSkillsFunc: func(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error) {
			if len(in.WorkProfileIDs) != 1 || in.WorkProfileIDs[0] != workProfileID {
				t.Fatalf("expected work profile id %s, got %+v", workProfileID, in.WorkProfileIDs)
			}
			return &models.BatchListEffectiveWorkProfileSkillsResult{
				SkillGrantsByWorkProfileID: map[uuid.UUID][]*models.WorkProfileSkillGrant{
					workProfileID: {{SkillID: skillID, Active: true}},
				},
			}, nil
		},
	}), zap.NewNop())

	result, err := svc.BatchListEffectiveWorkProfileSkills(context.Background(), &models.BatchListEffectiveWorkProfileSkillsInput{
		WorkProfileIDs: []uuid.UUID{workProfileID},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result.SkillGrantsByWorkProfileID[workProfileID]) != 1 {
		t.Fatalf("expected one skill grant, got %+v", result.SkillGrantsByWorkProfileID)
	}
}
