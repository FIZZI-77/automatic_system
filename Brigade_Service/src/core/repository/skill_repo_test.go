package repository

import (
	"brigade/models"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSkillRepository_CreateListUpdateDeactivate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()

	created, err := repo.CreateSkill(ctx, &models.CreateSkillInput{Code: "plumbing", Name: "Plumbing"})
	if err != nil {
		t.Fatalf("create skill failed: %v", err)
	}
	if !created.Skill.Active {
		t.Fatal("expected skill active")
	}

	list, err := repo.ListSkills(ctx, &models.ListSkillsInput{Limit: 10})
	if err != nil {
		t.Fatalf("list skills failed: %v", err)
	}
	if list.Total != 1 || len(list.Skills) != 1 {
		t.Fatalf("expected one skill, got total=%d len=%d", list.Total, len(list.Skills))
	}

	name := "Water plumbing"
	updated, err := repo.UpdateSkill(ctx, &models.UpdateSkillInput{ID: created.Skill.ID, Name: &name})
	if err != nil {
		t.Fatalf("update skill failed: %v", err)
	}
	if updated.Skill.Name != name {
		t.Fatalf("expected name %s, got %s", name, updated.Skill.Name)
	}

	deactivated, err := repo.DeactivateSkill(ctx, &models.DeactivateSkillInput{ID: created.Skill.ID})
	if err != nil {
		t.Fatalf("deactivate skill failed: %v", err)
	}
	if deactivated.Skill.Active {
		t.Fatal("expected skill inactive")
	}
}

func TestSkillRepository_DuplicateCode(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()

	_, err := repo.CreateSkill(ctx, &models.CreateSkillInput{Code: "plumbing", Name: "Plumbing"})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = repo.CreateSkill(ctx, &models.CreateSkillInput{Code: "plumbing", Name: "Other"})
	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}
}

func TestSkillRepository_BrigadeSkills(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewRepository(DBPools{Write: db, Read: db})
	ctx := context.Background()
	brigade := createTestBrigade(t, repo, uuid.New())
	skill := createTestSkill(t, repo)

	added, err := repo.AddBrigadeSkill(ctx, &models.AddBrigadeSkillInput{BrigadeID: brigade.ID, SkillID: skill.ID})
	if err != nil {
		t.Fatalf("add brigade skill failed: %v", err)
	}
	if added.BrigadeSkill.SkillID != skill.ID {
		t.Fatalf("expected skill id %s, got %s", skill.ID, added.BrigadeSkill.SkillID)
	}

	list, err := repo.ListBrigadeSkills(ctx, &models.ListBrigadeSkillsInput{BrigadeID: brigade.ID})
	if err != nil {
		t.Fatalf("list brigade skills failed: %v", err)
	}
	if len(list.Skills) != 1 || list.Skills[0].Skill.Code == "" {
		t.Fatalf("expected joined skill, got %#v", list.Skills)
	}

	removed, err := repo.RemoveBrigadeSkill(ctx, &models.RemoveBrigadeSkillInput{BrigadeID: brigade.ID, SkillID: skill.ID})
	if err != nil {
		t.Fatalf("remove brigade skill failed: %v", err)
	}
	if removed.BrigadeSkill.Active {
		t.Fatal("expected brigade skill inactive")
	}
}
