package repository

import (
	"brigade/models"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SkillRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

// NewSkillRepo создаёт хранилище навыков с заданными ненулевыми пулами записи и чтения.
func NewSkillRepo(writePool *pgxpool.Pool, readPool *pgxpool.Pool) *SkillRepoStruct {
	return &SkillRepoStruct{writePool: writePool, readPool: readPool}
}

// CreateSkill сохраняет навык каталога и событие создания в одной транзакции.
// Нарушение уникальности кода преобразует в ErrAlreadyExists.
func (s *SkillRepoStruct) CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error) {
	tx, err := s.writePool.Begin(ctx)

	if err != nil {
		return nil, fmt.Errorf("repo: CreateSkill: begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		INSERT INTO skills (code, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, code, name, description, active, created_at, updated_at
	`

	skill, err := scanSkill(tx.QueryRow(ctx, query, in.Code, in.Name, in.Description))

	if err != nil {

		if isSkillUniqueViolation(err) {
			return nil, fmt.Errorf("repo: CreateSkill: %w", models.ErrAlreadyExists)
		}

		return nil, fmt.Errorf("repo: CreateSkill: scan skill: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "SkillCreated",
		"skill_id":   skill.ID.String(),
		"code":       skill.Code,
		"name":       skill.Name,
		"created_at": skill.CreatedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "skill", skill.ID, "SkillCreated", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: CreateSkill: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: CreateSkill: commit tx: %w", err)
	}

	return &models.CreateSkillResult{Skill: skill}, nil
}

// UpdateSkill транзакционно меняет ненулевые поля навыка и записывает outbox.
// Отсутствие даёт ErrNotFound, дубликат кода — ErrAlreadyExists; nil поля сохраняет.
func (s *SkillRepoStruct) UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error) {
	tx, err := s.writePool.Begin(ctx)

	if err != nil {
		return nil, fmt.Errorf("repo: UpdateSkill: begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE skills
		SET
			code = COALESCE($1, code),
			name = COALESCE($2, name),
			description = COALESCE($3, description),
			active = COALESCE($4, active),
			updated_at = now()
		WHERE id = $5
		RETURNING id, code, name, description, active, created_at, updated_at
	`

	skill, err := scanSkill(tx.QueryRow(ctx, query, in.Code, in.Name, in.Description, in.Active, in.ID))

	if err != nil {

		if isSkillUniqueViolation(err) {
			return nil, fmt.Errorf("repo: UpdateSkill: %w", models.ErrAlreadyExists)
		}

		return nil, fmt.Errorf("repo: UpdateSkill: scan skill: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "SkillUpdated",
		"skill_id":   skill.ID.String(),
		"code":       skill.Code,
		"name":       skill.Name,
		"active":     skill.Active,
		"updated_at": skill.UpdatedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "skill", skill.ID, "SkillUpdated", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: UpdateSkill: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: UpdateSkill: commit tx: %w", err)
	}

	return &models.UpdateSkillResult{Skill: skill}, nil
}

// DeactivateSkill транзакционно выключает навык и записывает outbox, не удаляя строку.
// Повтор допустим; отсутствие даёт ErrNotFound, связи бригад не изменяются.
func (s *SkillRepoStruct) DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error) {
	tx, err := s.writePool.Begin(ctx)

	if err != nil {
		return nil, fmt.Errorf("repo: DeactivateSkill: begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE skills
		SET active = false, updated_at = now()
		WHERE id = $1
		RETURNING id, code, name, description, active, created_at, updated_at
	`

	skill, err := scanSkill(tx.QueryRow(ctx, query, in.ID))

	if err != nil {
		return nil, fmt.Errorf("repo: DeactivateSkill: scan skill: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "SkillDeactivated",
		"skill_id":   skill.ID.String(),
		"code":       skill.Code,
		"updated_at": skill.UpdatedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "skill", skill.ID, "SkillDeactivated", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: DeactivateSkill: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: DeactivateSkill: commit tx: %w", err)
	}

	return &models.DeactivateSkillResult{Skill: skill}, nil
}

// ListSkills возвращает страницу каталога по активности и поиску ILIKE по коду
// или имени, сортируя по коду ASC, с отдельным общим счётчиком.
// Пагинацию должен подготовить вызывающий код.
func (s *SkillRepoStruct) ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error) {
	whereParts := make([]string, 0)
	args := make([]any, 0)
	addWhere := func(condition string, value any) {
		args = append(args, value)
		whereParts = append(whereParts, fmt.Sprintf(condition, len(args)))
	}

	if in.Active != nil {
		addWhere("active = $%d", *in.Active)
	}

	if in.Query != nil {
		addWhere("(code ILIKE $%d OR name ILIKE $%d)", "%"+*in.Query+"%")
		args = append(args, "%"+*in.Query+"%")
		whereParts[len(whereParts)-1] = fmt.Sprintf("(code ILIKE $%d OR name ILIKE $%d)", len(args)-1, len(args))
	}

	whereSQL := ""

	if len(whereParts) > 0 {
		whereSQL = "WHERE " + strings.Join(whereParts, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM skills %s", whereSQL)
	var total int64

	if err := s.readPool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("repo: ListSkills: count: %w", err)
	}

	args = append(args, in.Limit, in.Offset)
	query := fmt.Sprintf(`
		SELECT id, code, name, description, active, created_at, updated_at
		FROM skills
		%s
		ORDER BY code ASC
		LIMIT $%d OFFSET $%d
	`, whereSQL, len(args)-1, len(args))

	rows, err := s.readPool.Query(ctx, query, args...)

	if err != nil {
		return nil, fmt.Errorf("repo: ListSkills: query: %w", err)
	}

	defer rows.Close()

	skills := make([]*models.Skill, 0)
	for rows.Next() {
		skill, err := scanSkill(rows)

		if err != nil {
			return nil, fmt.Errorf("repo: ListSkills: scan: %w", err)
		}

		skills = append(skills, skill)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: ListSkills: rows: %w", err)
	}

	return &models.ListSkillsResult{Skills: skills, Total: total}, nil
}

// AddBrigadeSkill вставляет связь бригады с навыком и событие outbox в одной транзакции.
// Конфликт активной связи даёт ErrAlreadyExists; прежнюю неактивную строку не восстанавливает.
func (s *SkillRepoStruct) AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error) {
	tx, err := s.writePool.Begin(ctx)

	if err != nil {
		return nil, fmt.Errorf("repo: AddBrigadeSkill: begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		INSERT INTO brigade_skills (brigade_id, skill_id)
		VALUES ($1, $2)
		RETURNING id, brigade_id, skill_id, active, created_at, updated_at
	`

	brigadeSkill, err := scanBrigadeSkill(tx.QueryRow(ctx, query, in.BrigadeID, in.SkillID))

	if err != nil {

		if isBrigadeSkillUniqueViolation(err) {
			return nil, fmt.Errorf("repo: AddBrigadeSkill: %w", models.ErrAlreadyExists)
		}

		return nil, fmt.Errorf("repo: AddBrigadeSkill: scan brigade skill: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeSkillAdded",
		"brigade_id": in.BrigadeID.String(),
		"skill_id":   in.SkillID.String(),
		"created_at": brigadeSkill.CreatedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", in.BrigadeID, "BrigadeSkillAdded", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: AddBrigadeSkill: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: AddBrigadeSkill: commit tx: %w", err)
	}

	return &models.AddBrigadeSkillResult{BrigadeSkill: brigadeSkill}, nil
}

// RemoveBrigadeSkill деактивирует связи по паре бригада–навык и записывает outbox
// в одной транзакции. Повторное выключение допустимо; отсутствие даёт ErrNotFound.
func (s *SkillRepoStruct) RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error) {
	tx, err := s.writePool.Begin(ctx)

	if err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeSkill: begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE brigade_skills
		SET active = false, updated_at = now()
		WHERE brigade_id = $1 AND skill_id = $2
		RETURNING id, brigade_id, skill_id, active, created_at, updated_at
	`

	brigadeSkill, err := scanBrigadeSkill(tx.QueryRow(ctx, query, in.BrigadeID, in.SkillID))

	if err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeSkill: scan brigade skill: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeSkillRemoved",
		"brigade_id": in.BrigadeID.String(),
		"skill_id":   in.SkillID.String(),
		"updated_at": brigadeSkill.UpdatedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", in.BrigadeID, "BrigadeSkillRemoved", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeSkill: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeSkill: commit tx: %w", err)
	}

	return &models.RemoveBrigadeSkillResult{BrigadeSkill: brigadeSkill}, nil
}

// ListBrigadeSkills возвращает связи бригады с вложенными данными навыков по коду ASC.
// Фильтр Active применяется к связи, а не активности самого навыка.
func (s *SkillRepoStruct) ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error) {
	whereParts := []string{"bs.brigade_id = $1"}
	args := []any{in.BrigadeID}

	if in.Active != nil {
		args = append(args, *in.Active)
		whereParts = append(whereParts, fmt.Sprintf("bs.active = $%d", len(args)))
	}

	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")

	query := fmt.Sprintf(`
		SELECT
			bs.id,
			bs.brigade_id,
			bs.skill_id,
			bs.active,
			bs.created_at,
			bs.updated_at,
			s.id,
			s.code,
			s.name,
			s.description,
			s.active,
			s.created_at,
			s.updated_at
		FROM brigade_skills bs
		JOIN skills s ON s.id = bs.skill_id
		%s
		ORDER BY s.code ASC
	`, whereSQL)

	rows, err := s.readPool.Query(ctx, query, args...)

	if err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeSkills: query: %w", err)
	}

	defer rows.Close()

	skills := make([]*models.BrigadeSkill, 0)
	for rows.Next() {
		item, err := scanBrigadeSkillWithSkill(rows)

		if err != nil {
			return nil, fmt.Errorf("repo: ListBrigadeSkills: scan: %w", err)
		}

		skills = append(skills, item)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeSkills: rows: %w", err)
	}

	return &models.ListBrigadeSkillsResult{Skills: skills}, nil
}

// scanSkill читает навык и преобразует pgx.ErrNoRows в ErrNotFound.
func scanSkill(row scanner) (*models.Skill, error) {
	var skill models.Skill
	err := row.Scan(&skill.ID, &skill.Code, &skill.Name, &skill.Description, &skill.Active, &skill.CreatedAt, &skill.UpdatedAt)

	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}

		return nil, err
	}

	return &skill, nil
}

// scanBrigadeSkill читает связь бригады с навыком и преобразует pgx.ErrNoRows в ErrNotFound.
func scanBrigadeSkill(row scanner) (*models.BrigadeSkill, error) {
	var item models.BrigadeSkill
	err := row.Scan(&item.ID, &item.BrigadeID, &item.SkillID, &item.Active, &item.CreatedAt, &item.UpdatedAt)

	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}

		return nil, err
	}

	return &item, nil
}

// scanBrigadeSkillWithSkill читает связь с данными навыка в поле Skill.
// pgx.ErrNoRows преобразует в ErrNotFound.
func scanBrigadeSkillWithSkill(row scanner) (*models.BrigadeSkill, error) {
	item, skill, err := scanBrigadeSkillWithSkillRaw(row)

	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}

		return nil, err
	}

	item.Skill = skill
	return item, nil
}

// scanBrigadeSkillWithSkillRaw читает связь и навык в отдельные модели.
// Ошибку Scan, включая pgx.ErrNoRows, возвращает без замены.
func scanBrigadeSkillWithSkillRaw(row scanner) (*models.BrigadeSkill, *models.Skill, error) {
	var item models.BrigadeSkill
	var skill models.Skill
	err := row.Scan(
		&item.ID,
		&item.BrigadeID,
		&item.SkillID,
		&item.Active,
		&item.CreatedAt,
		&item.UpdatedAt,
		&skill.ID,
		&skill.Code,
		&skill.Name,
		&skill.Description,
		&skill.Active,
		&skill.CreatedAt,
		&skill.UpdatedAt,
	)

	if err != nil {
		return nil, nil, err
	}

	return &item, &skill, nil
}

// brigadeHasSkills сравнивает число уникальных активных связей с длиной skillIDs.
// Пустой список даёт true без запроса; повтор ID может привести к false,
// активность самого навыка не учитывается.
func (s *SkillRepoStruct) brigadeHasSkills(ctx context.Context, brigadeID uuid.UUID, skillIDs []uuid.UUID) (bool, error) {

	if len(skillIDs) == 0 {
		return true, nil
	}

	const query = `
		SELECT COUNT(DISTINCT skill_id)
		FROM brigade_skills
		WHERE brigade_id = $1
		  AND active = true
		  AND skill_id = ANY($2)
	`

	var count int

	if err := s.readPool.QueryRow(ctx, query, brigadeID, uuidStrings(skillIDs)).Scan(&count); err != nil {
		return false, err
	}

	return count == len(skillIDs), nil
}

// isSkillUniqueViolation распознаёт PostgreSQL 23505 без имени ограничения
// либо с именем skills_code_uidx в цепочке err.
func isSkillUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError

	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName == "" || pgErr.ConstraintName == "skills_code_uidx"
	}

	return false
}

// isBrigadeSkillUniqueViolation распознаёт PostgreSQL 23505 без имени ограничения
// либо с именем brigade_skills_active_uidx в цепочке err.
func isBrigadeSkillUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError

	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName == "" || pgErr.ConstraintName == "brigade_skills_active_uidx"
	}

	return false
}
