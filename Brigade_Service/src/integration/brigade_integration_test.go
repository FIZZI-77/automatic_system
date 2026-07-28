package integration

import (
	"brigade/models"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

const integrationZoneGeoJSON = `{
	"type": "Polygon",
	"coordinates": [[[37.0,55.0],[38.0,55.0],[38.0,56.0],[37.0,56.0],[37.0,55.0]]]
}`

func TestBrigadeServiceIntegration_CreateManageAndFind(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	ctx := context.Background()
	departmentID := uuid.New()
	actorID := uuid.New()

	createResult, err := app.service.CreateBrigade(ctx, &models.CreateBrigadeInput{
		DepartmentID:      departmentID,
		Name:              uniqueName("brigade"),
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("create brigade failed: %v", err)
	}
	brigadeID := createResult.Brigade.ID

	skillResult, err := app.service.CreateSkill(ctx, &models.CreateSkillInput{
		Code:       uniqueName("skill"),
		Name:       "Integration skill",
		ActorRoles: []string{"admin"},
	})
	if err != nil {
		t.Fatalf("create skill failed: %v", err)
	}
	app.profile.skillIDs = []uuid.UUID{skillResult.Skill.ID}

	memberResult, err := app.service.AddBrigadeMember(ctx, &models.AddBrigadeMemberInput{
		BrigadeID:         brigadeID,
		UserID:            uuid.New(),
		Role:              models.BrigadeMemberRoleLead,
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("add member failed: %v", err)
	}
	if memberResult.Member.ID == uuid.Nil {
		t.Fatal("expected member id")
	}

	_, err = app.service.AddBrigadeSkill(ctx, &models.AddBrigadeSkillInput{
		BrigadeID:         brigadeID,
		SkillID:           skillResult.Skill.ID,
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("add brigade skill failed: %v", err)
	}

	_, err = app.service.SetBrigadeStatus(ctx, &models.SetBrigadeStatusInput{
		BrigadeID:         brigadeID,
		Status:            models.BrigadeStatusActive,
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("set active status failed: %v", err)
	}

	dayOfWeek := int16(time.Now().UTC().Weekday())
	if dayOfWeek == 0 {
		dayOfWeek = 7
	}

	_, err = app.service.SetBrigadeSchedule(ctx, &models.SetBrigadeScheduleInput{
		BrigadeID: brigadeID,
		Items: []*models.BrigadeScheduleItem{{
			DayOfWeek: dayOfWeek,
			StartsAt:  "00:00",
			EndsAt:    "23:59",
			Timezone:  "UTC",
		}},
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("set schedule failed: %v", err)
	}

	_, err = app.service.CreateBrigadeZone(ctx, &models.CreateBrigadeZoneInput{
		BrigadeID:         brigadeID,
		DepartmentID:      departmentID,
		Name:              "North",
		GeoJSON:           integrationZoneGeoJSON,
		Priority:          10,
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("create zone failed: %v", err)
	}

	_, err = app.service.SetBrigadeStatus(ctx, &models.SetBrigadeStatusInput{
		BrigadeID:         brigadeID,
		Status:            models.BrigadeStatusAvailable,
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err != nil {
		t.Fatalf("set available status failed: %v", err)
	}

	canHandle, err := app.service.CheckBrigadeCanHandleTicket(ctx, &models.CheckBrigadeCanHandleTicketInput{
		BrigadeID:        brigadeID,
		DepartmentID:     departmentID,
		Longitude:        37.5,
		Latitude:         55.5,
		RequiredSkillIDs: []uuid.UUID{skillResult.Skill.ID},
		RequiredRoles:    []models.BrigadeMemberRole{models.BrigadeMemberRoleLead},
	})
	if err != nil {
		t.Fatalf("check can handle ticket failed: %v", err)
	}
	if !canHandle.CanHandle {
		t.Fatalf("expected brigade can handle ticket, reasons: %#v", canHandle.Reasons)
	}
}

func TestBrigadeServiceIntegration_DispatcherWrongDepartmentDenied(t *testing.T) {
	app := newTestApp(t)
	defer app.cleanup()

	departmentID := uuid.New()
	otherDepartmentID := uuid.New()
	actorID := uuid.New()

	_, err := app.service.CreateBrigade(context.Background(), &models.CreateBrigadeInput{
		DepartmentID:      departmentID,
		Name:              uniqueName("brigade"),
		ActorUserID:       &actorID,
		ActorDepartmentID: &otherDepartmentID,
		ActorRoles:        []string{"dispatcher"},
	})
	if err == nil {
		t.Fatal("expected permission denied")
	}
}
