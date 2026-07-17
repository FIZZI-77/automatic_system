package models

import (
	"testing"

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
