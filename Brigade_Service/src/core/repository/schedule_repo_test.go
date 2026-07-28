package repository

import (
	"brigade/models"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestScheduleRepository_SetAndList(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	brigade := createTestBrigade(t, repo, uuid.New())
	from := time.Now()
	to := from.AddDate(0, 1, 0)

	result, err := repo.SetBrigadeSchedule(ctx, &models.SetBrigadeScheduleInput{
		BrigadeID: brigade.ID,
		Items: []*models.BrigadeScheduleItem{{
			DayOfWeek: 1,
			StartsAt:  "09:00",
			EndsAt:    "18:00",
			Timezone:  "UTC",
			ValidFrom: &from,
			ValidTo:   &to,
		}},
	})
	if err != nil {
		t.Fatalf("set schedule failed: %v", err)
	}
	if len(result.Schedule) != 1 {
		t.Fatalf("expected one schedule item, got %d", len(result.Schedule))
	}

	active := true
	list, err := repo.ListBrigadeSchedule(ctx, &models.ListBrigadeScheduleInput{BrigadeID: brigade.ID, Active: &active})
	if err != nil {
		t.Fatalf("list schedule failed: %v", err)
	}
	if len(list.Schedule) != 1 {
		t.Fatalf("expected one active schedule item, got %d", len(list.Schedule))
	}

	_, err = repo.SetBrigadeSchedule(ctx, &models.SetBrigadeScheduleInput{
		BrigadeID: brigade.ID,
		Items: []*models.BrigadeScheduleItem{{
			DayOfWeek: 2,
			StartsAt:  "10:00",
			EndsAt:    "17:00",
		}},
	})
	if err != nil {
		t.Fatalf("replace schedule failed: %v", err)
	}

	all, err := repo.ListBrigadeSchedule(ctx, &models.ListBrigadeScheduleInput{BrigadeID: brigade.ID})
	if err != nil {
		t.Fatalf("list all schedule failed: %v", err)
	}
	if len(all.Schedule) != 2 {
		t.Fatalf("expected old inactive plus new active schedule, got %d", len(all.Schedule))
	}
}
