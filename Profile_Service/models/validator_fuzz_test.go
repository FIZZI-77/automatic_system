package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func FuzzCreateUserProfileInputValidate(f *testing.F) {
	f.Add(uuid.New().String(), "Иван Иванов", "+79991234567", "PHONE", true)
	f.Add("bad-id", "", "bad-phone", "BAD", true)
	f.Add(uuid.Nil.String(), "A", "", "EMAIL", false)

	f.Fuzz(func(t *testing.T, userIDRaw string, fullName string, phoneRaw string, methodRaw string, includePhone bool) {
		userID, _ := uuid.Parse(userIDRaw)
		var phone *string
		if includePhone {
			phone = &phoneRaw
		}
		in := &CreateUserProfileInput{
			UserID:                 userID,
			FullName:               fullName,
			Phone:                  phone,
			PreferredContactMethod: PreferredContactMethod(methodRaw),
		}
		_ = in.Validate()
	})
}

func FuzzCheckProfileCanJoinBrigadeInputValidate(f *testing.F) {
	f.Add(uuid.New().String(), uuid.New().String(), uuid.New().String(), true, false)
	f.Add("", "", "", false, false)
	f.Add("bad", "bad", "bad", true, true)

	f.Fuzz(func(t *testing.T, userIDRaw string, workProfileIDRaw string, departmentIDRaw string, includeUser bool, includeWorkProfile bool) {
		userID, _ := uuid.Parse(userIDRaw)
		workProfileID, _ := uuid.Parse(workProfileIDRaw)
		departmentID, _ := uuid.Parse(departmentIDRaw)
		var userIDPtr *uuid.UUID
		var workProfileIDPtr *uuid.UUID
		if includeUser {
			userIDPtr = &userID
		}
		if includeWorkProfile {
			workProfileIDPtr = &workProfileID
		}
		in := &CheckProfileCanJoinBrigadeInput{
			UserID:              userIDPtr,
			WorkProfileID:       workProfileIDPtr,
			BrigadeDepartmentID: departmentID,
		}
		_ = in.Validate()
	})
}

func FuzzCreateWorkProfileInputValidate(f *testing.F) {
	f.Add(uuid.NewString(), uuid.NewString(), "EMP-001", "Engineer", true)
	f.Add("", "", "", "", false)
	f.Add("bad-id", "bad-department", " ", "A", true)
	f.Add(uuid.Nil.String(), uuid.Nil.String(), "employee", "Dispatcher", true)

	f.Fuzz(func(t *testing.T, userProfileIDRaw string, departmentIDRaw string, employeeNumberRaw string, position string, includeEmployeeNumber bool) {
		userProfileID, _ := uuid.Parse(userProfileIDRaw)
		departmentID, _ := uuid.Parse(departmentIDRaw)

		var employeeNumber *string
		if includeEmployeeNumber {
			employeeNumber = &employeeNumberRaw
		}

		in := &CreateWorkProfileInput{
			UserProfileID:  userProfileID,
			DepartmentID:   departmentID,
			EmployeeNumber: employeeNumber,
			Position:       position,
		}
		_ = in.Validate()
	})
}

func FuzzUploadWorkProfileCertificationInputValidate(f *testing.F) {
	now := time.Now().UTC()
	f.Add(uuid.NewString(), uuid.NewString(), uuid.NewString(), "CERT-001", "Issuer", int64(0), int64(24), true, true, true)
	f.Add("", "", "", "", "", int64(24), int64(0), false, false, false)
	f.Add("bad-work-profile", "bad-type", "bad-file", " ", " ", int64(10), int64(-10), true, true, true)

	f.Fuzz(func(t *testing.T, workProfileIDRaw string, certificationTypeIDRaw string, fileIDRaw string, certificateNumberRaw string, issuerRaw string, issuedOffsetHours int64, expiresOffsetHours int64, includeFile bool, includeIssued bool, includeExpires bool) {
		workProfileID, _ := uuid.Parse(workProfileIDRaw)
		certificationTypeID, _ := uuid.Parse(certificationTypeIDRaw)
		fileID, _ := uuid.Parse(fileIDRaw)

		var fileIDPtr *uuid.UUID
		if includeFile {
			fileIDPtr = &fileID
		}

		var issuedAt *time.Time
		if includeIssued {
			value := now.Add(time.Duration(issuedOffsetHours) * time.Hour)
			issuedAt = &value
		}

		var expiresAt *time.Time
		if includeExpires {
			value := now.Add(time.Duration(expiresOffsetHours) * time.Hour)
			expiresAt = &value
		}

		in := &UploadWorkProfileCertificationInput{
			WorkProfileID:       workProfileID,
			CertificationTypeID: certificationTypeID,
			CertificateNumber:   &certificateNumberRaw,
			Issuer:              &issuerRaw,
			IssuedAt:            issuedAt,
			ExpiresAt:           expiresAt,
			CertificateFileID:   fileIDPtr,
		}
		_ = in.Validate()
	})
}

func FuzzGrantManualWorkProfileSkillInputValidate(f *testing.F) {
	now := time.Now().UTC()
	f.Add(uuid.NewString(), uuid.NewString(), "senior", int64(24), "manual grant", true, true)
	f.Add("", "", "", int64(-1), "", false, false)
	f.Add("bad-work-profile", "bad-skill", " ", int64(0), " ", true, true)

	f.Fuzz(func(t *testing.T, workProfileIDRaw string, skillIDRaw string, proficiencyLevelRaw string, validUntilOffsetHours int64, reason string, includeProficiency bool, includeValidUntil bool) {
		workProfileID, _ := uuid.Parse(workProfileIDRaw)
		skillID, _ := uuid.Parse(skillIDRaw)

		var proficiencyLevel *string
		if includeProficiency {
			proficiencyLevel = &proficiencyLevelRaw
		}

		var validUntil *time.Time
		if includeValidUntil {
			value := now.Add(time.Duration(validUntilOffsetHours) * time.Hour)
			validUntil = &value
		}

		in := &GrantManualWorkProfileSkillInput{
			WorkProfileID:    workProfileID,
			SkillID:          skillID,
			ProficiencyLevel: proficiencyLevel,
			ValidUntil:       validUntil,
			Reason:           reason,
		}
		_ = in.Validate()
	})
}

func FuzzBatchListEffectiveWorkProfileSkillsInputValidate(f *testing.F) {
	firstID := uuid.NewString()
	secondID := uuid.NewString()
	f.Add(firstID, secondID, true, true)
	f.Add("", "", false, false)
	f.Add("bad-first", "bad-second", true, true)
	f.Add(firstID, firstID, true, true)

	f.Fuzz(func(t *testing.T, firstRaw string, secondRaw string, includeFirst bool, includeSecond bool) {
		var ids []uuid.UUID
		if includeFirst {
			firstID, _ := uuid.Parse(firstRaw)
			ids = append(ids, firstID)
		}
		if includeSecond {
			secondID, _ := uuid.Parse(secondRaw)
			ids = append(ids, secondID)
		}

		in := &BatchListEffectiveWorkProfileSkillsInput{WorkProfileIDs: ids}
		_ = in.Validate()
	})
}

func FuzzCheckWorkProfileHasSkillsInputValidate(f *testing.F) {
	f.Add(uuid.NewString(), uuid.NewString(), uuid.NewString(), true, true)
	f.Add("", "", "", false, false)
	f.Add("bad-work-profile", "bad-skill", "bad-skill-2", true, true)

	f.Fuzz(func(t *testing.T, workProfileIDRaw string, firstSkillIDRaw string, secondSkillIDRaw string, includeFirstSkill bool, includeSecondSkill bool) {
		workProfileID, _ := uuid.Parse(workProfileIDRaw)
		var skillIDs []uuid.UUID
		if includeFirstSkill {
			skillID, _ := uuid.Parse(firstSkillIDRaw)
			skillIDs = append(skillIDs, skillID)
		}
		if includeSecondSkill {
			skillID, _ := uuid.Parse(secondSkillIDRaw)
			skillIDs = append(skillIDs, skillID)
		}

		in := &CheckWorkProfileHasSkillsInput{
			WorkProfileID:    workProfileID,
			RequiredSkillIDs: skillIDs,
		}
		_ = in.Validate()
	})
}
