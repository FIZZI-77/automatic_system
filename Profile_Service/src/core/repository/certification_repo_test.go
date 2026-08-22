package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"profile/models"
)

func TestCertificationRepository_TypeAndSkills(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	certificationType := createTestCertificationType(t, repo, false)
	skillID := uuid.New()
	level := "senior"

	link, err := repo.AddCertificationTypeSkill(ctx, &models.AddCertificationTypeSkillInput{
		CertificationTypeID: certificationType.ID,
		SkillID:             skillID,
		ProficiencyLevel:    &level,
	})
	if err != nil {
		t.Fatalf("add certification type skill failed: %v", err)
	}
	if link.CertificationTypeSkill.SkillID != skillID {
		t.Fatalf("expected skill id %s, got %s", skillID, link.CertificationTypeSkill.SkillID)
	}

	list, err := repo.ListCertificationTypeSkills(ctx, &models.ListCertificationTypeSkillsInput{
		CertificationTypeID: certificationType.ID,
		ActiveOnly:          true,
	})
	if err != nil {
		t.Fatalf("list certification type skills failed: %v", err)
	}
	if len(list.Skills) != 1 {
		t.Fatalf("expected one active skill, got %d", len(list.Skills))
	}

	if err = repo.RemoveCertificationTypeSkill(ctx, &models.RemoveCertificationTypeSkillInput{
		CertificationTypeID: certificationType.ID,
		SkillID:             skillID,
	}); err != nil {
		t.Fatalf("remove certification type skill failed: %v", err)
	}

	list, err = repo.ListCertificationTypeSkills(ctx, &models.ListCertificationTypeSkillsInput{
		CertificationTypeID: certificationType.ID,
		ActiveOnly:          true,
	})
	if err != nil {
		t.Fatalf("list certification type skills after remove failed: %v", err)
	}
	if len(list.Skills) != 0 {
		t.Fatalf("expected no active skills, got %d", len(list.Skills))
	}

	newName := "Updated certification"
	active := false
	updated, err := repo.UpdateCertificationType(ctx, &models.UpdateCertificationTypeInput{
		ID:     certificationType.ID,
		Name:   &newName,
		Active: &active,
	})
	if err != nil {
		t.Fatalf("update certification type failed: %v", err)
	}
	if updated.CertificationType.Name != newName || updated.CertificationType.Active {
		t.Fatalf("unexpected updated certification type: %+v", updated.CertificationType)
	}
}

func TestCertificationRepository_VerifyCertificationGrantsAndRevokesSkills(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userProfile := createTestUserProfile(t, repo)
	workProfile := createTestWorkProfile(t, repo, userProfile.ID, uuid.New())
	certificationType := createTestCertificationType(t, repo, false)
	skillID := uuid.New()

	_, err := repo.AddCertificationTypeSkill(ctx, &models.AddCertificationTypeSkillInput{
		CertificationTypeID: certificationType.ID,
		SkillID:             skillID,
	})
	if err != nil {
		t.Fatalf("add certification type skill failed: %v", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	upload, err := repo.UploadWorkProfileCertification(ctx, &models.UploadWorkProfileCertificationInput{
		WorkProfileID:       workProfile.WorkProfile.ID,
		CertificationTypeID: certificationType.ID,
		ExpiresAt:           &expiresAt,
	})
	if err != nil {
		t.Fatalf("upload work profile certification failed: %v", err)
	}
	if upload.Certification.Status != models.CertificationStatusPending {
		t.Fatalf("expected PENDING, got %s", upload.Certification.Status)
	}

	verifierID := uuid.New()
	verify, err := repo.VerifyWorkProfileCertification(ctx, &models.VerifyWorkProfileCertificationInput{
		ID:          upload.Certification.ID,
		ActorUserID: &verifierID,
	})
	if err != nil {
		t.Fatalf("verify certification failed: %v", err)
	}
	if verify.Certification.Status != models.CertificationStatusVerified {
		t.Fatalf("expected VERIFIED, got %s", verify.Certification.Status)
	}
	if len(verify.SkillGrants) != 1 || verify.SkillGrants[0].SkillID != skillID {
		t.Fatalf("expected one skill grant for %s, got %+v", skillID, verify.SkillGrants)
	}

	effective, err := repo.ListEffectiveWorkProfileSkills(ctx, &models.ListEffectiveWorkProfileSkillsInput{WorkProfileID: workProfile.WorkProfile.ID})
	if err != nil {
		t.Fatalf("list effective work profile skills failed: %v", err)
	}
	if len(effective.SkillGrants) != 1 {
		t.Fatalf("expected one effective skill, got %d", len(effective.SkillGrants))
	}

	check, err := repo.CheckWorkProfileHasSkills(ctx, &models.CheckWorkProfileHasSkillsInput{
		WorkProfileID:    workProfile.WorkProfile.ID,
		RequiredSkillIDs: []uuid.UUID{skillID},
	})
	if err != nil {
		t.Fatalf("check work profile skills failed: %v", err)
	}
	if !check.Allowed {
		t.Fatalf("expected allowed skill check, missing %+v", check.MissingSkillIDs)
	}

	revoke, err := repo.RevokeWorkProfileCertification(ctx, &models.RevokeWorkProfileCertificationInput{
		ID:     upload.Certification.ID,
		Reason: "manual revoke",
	})
	if err != nil {
		t.Fatalf("revoke certification failed: %v", err)
	}
	if revoke.Certification.Status != models.CertificationStatusRevoked {
		t.Fatalf("expected REVOKED, got %s", revoke.Certification.Status)
	}
	if len(revoke.RevokedGrants) != 1 || revoke.RevokedGrants[0].Active {
		t.Fatalf("expected one inactive revoked grant, got %+v", revoke.RevokedGrants)
	}
}

func TestCertificationRepository_ManualSkillGrant(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userProfile := createTestUserProfile(t, repo)
	workProfile := createTestWorkProfile(t, repo, userProfile.ID, uuid.New())
	skillID := uuid.New()

	grant, err := repo.GrantManualWorkProfileSkill(ctx, &models.GrantManualWorkProfileSkillInput{
		WorkProfileID: workProfile.WorkProfile.ID,
		SkillID:       skillID,
		Reason:        "manual grant",
	})
	if err != nil {
		t.Fatalf("grant manual skill failed: %v", err)
	}
	if grant.SkillGrant.SourceType != models.SkillGrantSourceTypeManual {
		t.Fatalf("expected MANUAL source, got %s", grant.SkillGrant.SourceType)
	}

	batch, err := repo.BatchListEffectiveWorkProfileSkills(ctx, &models.BatchListEffectiveWorkProfileSkillsInput{
		WorkProfileIDs: []uuid.UUID{workProfile.WorkProfile.ID},
	})
	if err != nil {
		t.Fatalf("batch list effective skills failed: %v", err)
	}
	if len(batch.SkillGrantsByWorkProfileID[workProfile.WorkProfile.ID]) != 1 {
		t.Fatalf("expected one batch grant, got %+v", batch.SkillGrantsByWorkProfileID)
	}

	revoked, err := repo.RevokeWorkProfileSkillGrant(ctx, &models.RevokeWorkProfileSkillGrantInput{
		ID:     grant.SkillGrant.ID,
		Reason: "manual revoke",
	})
	if err != nil {
		t.Fatalf("revoke manual skill grant failed: %v", err)
	}
	if revoked.SkillGrant.Active {
		t.Fatal("expected grant to be inactive")
	}
	if revoked.SkillGrant.RevokedAt == nil {
		t.Fatal("expected revoked_at")
	}
}

func TestCertificationRepository_VerifyInvalidStatusFails(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	userProfile := createTestUserProfile(t, repo)
	workProfile := createTestWorkProfile(t, repo, userProfile.ID, uuid.New())
	certificationType := createTestCertificationType(t, repo, false)

	upload, err := repo.UploadWorkProfileCertification(ctx, &models.UploadWorkProfileCertificationInput{
		WorkProfileID:       workProfile.WorkProfile.ID,
		CertificationTypeID: certificationType.ID,
	})
	if err != nil {
		t.Fatalf("upload work profile certification failed: %v", err)
	}

	_, err = repo.RejectWorkProfileCertification(ctx, &models.RejectWorkProfileCertificationInput{
		ID:              upload.Certification.ID,
		RejectionReason: "bad document",
	})
	if err != nil {
		t.Fatalf("reject certification failed: %v", err)
	}

	_, err = repo.VerifyWorkProfileCertification(ctx, &models.VerifyWorkProfileCertificationInput{ID: upload.Certification.ID})
	if !errors.Is(err, models.ErrInvalidCertificationStatus) {
		t.Fatalf("expected invalid certification status, got %v", err)
	}
}
