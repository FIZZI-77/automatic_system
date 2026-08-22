package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"profile/models"
)

func TestProfileServiceIntegration_UserWorkAndStatusLifecycle(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	departmentID := uuid.New()

	userResult, err := app.service.CreateUserProfile(ctx, &models.CreateUserProfileInput{
		UserID:      userID,
		FullName:    "Ivan Ivanov",
		ActorUserID: &userID,
	})
	if err != nil {
		t.Fatalf("create user profile failed: %v", err)
	}
	if userResult.UserProfile.ID == uuid.Nil {
		t.Fatal("expected user profile id")
	}

	workResult, err := app.service.CreateWorkProfile(ctx, &models.CreateWorkProfileInput{
		UserProfileID: userResult.UserProfile.ID,
		DepartmentID:  departmentID,
		Position:      "Engineer",
		ActorRoles:    []string{"admin"},
	})
	if err != nil {
		t.Fatalf("create work profile failed: %v", err)
	}
	workProfileID := workResult.Details.WorkProfile.ID

	resolveResult, err := app.service.ResolveWorkingDepartment(ctx, &models.ResolveWorkingDepartmentInput{UserID: userID})
	if err != nil {
		t.Fatalf("resolve working department failed: %v", err)
	}
	if resolveResult.DepartmentID != departmentID || !resolveResult.CanOperate {
		t.Fatalf("unexpected resolve result: %+v", resolveResult)
	}

	statusResult, err := app.service.SetWorkProfileStatus(ctx, &models.SetWorkProfileStatusInput{
		ID:          workProfileID,
		Status:      models.WorkProfileStatusOnShift,
		Reason:      "start shift",
		ActorUserID: &userID,
	})
	if err != nil {
		t.Fatalf("set work profile status failed: %v", err)
	}
	if statusResult.Details.WorkProfile.Status != models.WorkProfileStatusOnShift {
		t.Fatalf("expected ON_SHIFT, got %s", statusResult.Details.WorkProfile.Status)
	}

	historyResult, err := app.service.GetWorkProfileStatusHistory(ctx, &models.GetWorkProfileStatusHistoryInput{
		WorkProfileID: workProfileID,
		ActorUserID:   &userID,
	})
	if err != nil {
		t.Fatalf("get status history failed: %v", err)
	}
	if historyResult.Total == 0 {
		t.Fatal("expected status history records")
	}
}

func TestProfileServiceIntegration_CertificationGrantsAndRevokesSkills(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	departmentID := uuid.New()
	skillID := uuid.New()
	verifierID := uuid.New()

	userResult, err := app.service.CreateUserProfile(ctx, &models.CreateUserProfileInput{
		UserID:      userID,
		FullName:    "Petr Petrov",
		ActorUserID: &userID,
	})
	if err != nil {
		t.Fatalf("create user profile failed: %v", err)
	}

	workResult, err := app.service.CreateWorkProfile(ctx, &models.CreateWorkProfileInput{
		UserProfileID: userResult.UserProfile.ID,
		DepartmentID:  departmentID,
		Position:      "Electrician",
		ActorRoles:    []string{"admin"},
	})
	if err != nil {
		t.Fatalf("create work profile failed: %v", err)
	}
	workProfileID := workResult.Details.WorkProfile.ID

	typeResult, err := app.service.CreateCertificationType(ctx, &models.CreateCertificationTypeInput{
		Code:         uniqueCode("electrical"),
		Name:         "Electrical safety",
		RequiresFile: false,
		ActorRoles:   []string{"admin"},
	})
	if err != nil {
		t.Fatalf("create certification type failed: %v", err)
	}

	_, err = app.service.AddCertificationTypeSkill(ctx, &models.AddCertificationTypeSkillInput{
		CertificationTypeID: typeResult.CertificationType.ID,
		SkillID:             skillID,
		ActorRoles:          []string{"admin"},
	})
	if err != nil {
		t.Fatalf("add certification type skill failed: %v", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	uploadResult, err := app.service.UploadWorkProfileCertification(ctx, &models.UploadWorkProfileCertificationInput{
		WorkProfileID:       workProfileID,
		CertificationTypeID: typeResult.CertificationType.ID,
		ExpiresAt:           &expiresAt,
		ActorUserID:         &userID,
	})
	if err != nil {
		t.Fatalf("upload certification failed: %v", err)
	}

	verifyResult, err := app.service.VerifyWorkProfileCertification(ctx, &models.VerifyWorkProfileCertificationInput{
		ID:          uploadResult.Certification.ID,
		ActorUserID: &verifierID,
		ActorRoles:  []string{"qualification_verifier"},
	})
	if err != nil {
		t.Fatalf("verify certification failed: %v", err)
	}
	if len(verifyResult.SkillGrants) != 1 || verifyResult.SkillGrants[0].SkillID != skillID {
		t.Fatalf("expected one grant for skill %s, got %+v", skillID, verifyResult.SkillGrants)
	}

	checkResult, err := app.service.CheckWorkProfileHasSkills(ctx, &models.CheckWorkProfileHasSkillsInput{
		WorkProfileID:    workProfileID,
		RequiredSkillIDs: []uuid.UUID{skillID},
		ActorUserID:      &userID,
	})
	if err != nil {
		t.Fatalf("check work profile skills failed: %v", err)
	}
	if !checkResult.Allowed {
		t.Fatalf("expected skill check allowed, missing: %+v", checkResult.MissingSkillIDs)
	}

	revokeResult, err := app.service.RevokeWorkProfileCertification(ctx, &models.RevokeWorkProfileCertificationInput{
		ID:          uploadResult.Certification.ID,
		Reason:      "expired manually",
		ActorUserID: &verifierID,
		ActorRoles:  []string{"hr"},
	})
	if err != nil {
		t.Fatalf("revoke certification failed: %v", err)
	}
	if len(revokeResult.RevokedGrants) != 1 {
		t.Fatalf("expected one revoked grant, got %+v", revokeResult.RevokedGrants)
	}
}

func TestProfileServiceIntegration_DuplicateUserProfileFails(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	userID := uuid.New()
	ctx := context.Background()

	_, err := app.service.CreateUserProfile(ctx, &models.CreateUserProfileInput{
		UserID:      userID,
		FullName:    "Duplicate User",
		ActorUserID: &userID,
	})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = app.service.CreateUserProfile(ctx, &models.CreateUserProfileInput{
		UserID:      userID,
		FullName:    "Duplicate User",
		ActorUserID: &userID,
	})
	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}
}
