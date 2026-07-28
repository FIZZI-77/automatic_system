package repository

import (
	"brigade/models"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type BrigadeRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

func NewBrigadeRepo(writePool *pgxpool.Pool, readPool *pgxpool.Pool) *BrigadeRepoStruct {
	return &BrigadeRepoStruct{writePool: writePool, readPool: readPool}
}

type scanner interface {
	Scan(dest ...any) error
}

type brigadeCreatedEventPayload struct {
	EventID        string    `json:"event_id"`
	EventType      string    `json:"event_type"`
	BrigadeID      string    `json:"brigade_id"`
	DepartmentID   string    `json:"department_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Status         string    `json:"status"`
	Specialization *string   `json:"specialization,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func (b *BrigadeRepoStruct) CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
	tx, err := b.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repo: CreateBrigade: begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	brigade, err := b.insertBrigade(ctx, tx, in)
	if err != nil {
		if isBrigadeNameUniqueViolation(err) {
			return nil, fmt.Errorf("repo: CreateBrigade: %w", models.ErrAlreadyExists)
		}
		return nil, fmt.Errorf("repo: CreateBrigade: insert brigade: %w", err)
	}

	payload := brigadeCreatedEventPayload{
		EventID:        uuid.NewString(),
		EventType:      "BrigadeCreated",
		BrigadeID:      brigade.ID.String(),
		DepartmentID:   brigade.DepartmentID.String(),
		Name:           brigade.Name,
		Description:    brigade.Description,
		Status:         string(brigade.Status),
		Specialization: brigade.Specialization,
		CreatedAt:      brigade.CreatedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", brigade.ID, "BrigadeCreated", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: CreateBrigade: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: CreateBrigade: commit tx: %w", err)
	}

	return &models.CreateBrigadeResult{Brigade: brigade}, nil
}

func (b *BrigadeRepoStruct) insertBrigade(ctx context.Context, tx pgx.Tx, in *models.CreateBrigadeInput) (*models.Brigade, error) {
	const query = `
		INSERT INTO brigades (
			department_id,
			name,
			description,
			specialization
		)
		VALUES ($1, $2, $3, $4)
		RETURNING
			id,
			department_id,
			name,
			description,
			status,
			specialization,
			created_at,
			updated_at,
			deactivated_at,
			archived_at
	`

	row := tx.QueryRow(ctx, query, in.DepartmentID, in.Name, in.Description, in.Specialization)
	return scanBrigade(row)
}

func (b *BrigadeRepoStruct) GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
	const query = `
		SELECT
			id,
			department_id,
			name,
			description,
			status,
			specialization,
			created_at,
			updated_at,
			deactivated_at,
			archived_at
		FROM brigades
		WHERE id = $1
	`

	row := b.readPool.QueryRow(ctx, query, in.ID)

	brigade, err := scanBrigade(row)
	if err != nil {
		return nil, fmt.Errorf("repo: GetBrigadeByID: scan brigade: %w", err)
	}

	return &models.GetBrigadeByIDResult{Brigade: brigade}, nil
}

func (b *BrigadeRepoStruct) ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error) {
	whereParts := make([]string, 0)
	args := make([]any, 0)

	addWhere := func(condition string, value any) {
		args = append(args, value)
		whereParts = append(whereParts, fmt.Sprintf(condition, len(args)))
	}

	if in.DepartmentID != nil {
		addWhere("department_id = $%d", *in.DepartmentID)
	}
	if in.Status != nil {
		addWhere("status = $%d", string(*in.Status))
	}
	if in.Specialization != nil {
		addWhere("specialization = $%d", *in.Specialization)
	}
	if in.CreatedFrom != nil {
		addWhere("created_at >= $%d", *in.CreatedFrom)
	}
	if in.CreatedTo != nil {
		addWhere("created_at <= $%d", *in.CreatedTo)
	}

	whereSQL := ""
	if len(whereParts) > 0 {
		whereSQL = "WHERE " + strings.Join(whereParts, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM brigades
		%s
	`, whereSQL)

	var total int64
	if err := b.readPool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("repo: ListBrigades: scan count: %w", err)
	}

	sortBy := brigadeSortBy(in.SortBy)
	sortOrder := brigadeSortOrder(in.SortOrder)

	args = append(args, in.Limit, in.Offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	listQuery := fmt.Sprintf(`
		SELECT
			id,
			department_id,
			name,
			description,
			status,
			specialization,
			created_at,
			updated_at,
			deactivated_at,
			archived_at
		FROM brigades
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereSQL, sortBy, sortOrder, limitArg, offsetArg)

	rows, err := b.readPool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: ListBrigades: query: %w", err)
	}
	defer rows.Close()

	brigades := make([]*models.Brigade, 0)

	for rows.Next() {
		brigade, err := scanBrigade(rows)
		if err != nil {
			return nil, fmt.Errorf("repo: ListBrigades: scan brigade: %w", err)
		}

		brigades = append(brigades, brigade)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: ListBrigades: rows: %w", err)
	}

	return &models.ListBrigadesResult{
		Brigades: brigades,
		Total:    total,
	}, nil
}

func (b *BrigadeRepoStruct) UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error) {
	tx, err := b.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigade: begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE brigades
		SET
			name = COALESCE($1, name),
			description = COALESCE($2, description),
			specialization = COALESCE($3, specialization),
			updated_at = now()
		WHERE id = $4
		RETURNING
			id,
			department_id,
			name,
			description,
			status,
			specialization,
			created_at,
			updated_at,
			deactivated_at,
			archived_at
	`

	brigade, err := scanBrigade(tx.QueryRow(ctx, query, in.Name, in.Description, in.Specialization, in.ID))
	if err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigade: scan brigade: %w", err)
	}

	payload := map[string]any{
		"event_id":      uuid.NewString(),
		"event_type":    "BrigadeUpdated",
		"brigade_id":    brigade.ID.String(),
		"department_id": brigade.DepartmentID.String(),
		"name":          brigade.Name,
		"description":   brigade.Description,
		"status":        brigade.Status,
		"updated_at":    brigade.UpdatedAt,
	}
	if brigade.Specialization != nil {
		payload["specialization"] = *brigade.Specialization
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", brigade.ID, "BrigadeUpdated", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigade: insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repo: UpdateBrigade: commit tx: %w", err)
	}

	return &models.UpdateBrigadeResult{Brigade: brigade}, nil
}

func (b *BrigadeRepoStruct) DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error) {
	brigade, err := b.setBrigadeStatusWithTx(ctx, in.ID, models.BrigadeStatusInactive, in.Reason, in.ChangedByUserID, in.RequestID, in.TraceID, true, false)
	if err != nil {
		return nil, fmt.Errorf("repo: DeactivateBrigade: %w", err)
	}

	return &models.DeactivateBrigadeResult{Brigade: brigade}, nil
}

func (b *BrigadeRepoStruct) ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error) {
	brigade, err := b.setBrigadeStatusWithTx(ctx, in.ID, models.BrigadeStatusArchived, in.Reason, in.ChangedByUserID, in.RequestID, in.TraceID, false, true)
	if err != nil {
		return nil, fmt.Errorf("repo: ArchiveBrigade: %w", err)
	}

	return &models.ArchiveBrigadeResult{Brigade: brigade}, nil
}

func (b *BrigadeRepoStruct) SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error) {
	brigade, err := b.setBrigadeStatusWithTx(ctx, in.BrigadeID, in.Status, in.Reason, in.ChangedByUserID, in.RequestID, in.TraceID, false, false)
	if err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeStatus: %w", err)
	}

	return &models.SetBrigadeStatusResult{Brigade: brigade}, nil
}

func (b *BrigadeRepoStruct) GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error) {
	const countQuery = `
		SELECT COUNT(*)
		FROM brigade_status_history
		WHERE brigade_id = $1
	`

	var total int64
	if err := b.readPool.QueryRow(ctx, countQuery, in.BrigadeID).Scan(&total); err != nil {
		return nil, fmt.Errorf("repo: GetBrigadeStatusHistory: count: %w", err)
	}

	const query = `
		SELECT
			id,
			brigade_id,
			from_status,
			to_status,
			reason,
			changed_by_user_id,
			request_id,
			created_at
		FROM brigade_status_history
		WHERE brigade_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := b.readPool.Query(ctx, query, in.BrigadeID, in.Limit, in.Offset)
	if err != nil {
		return nil, fmt.Errorf("repo: GetBrigadeStatusHistory: query: %w", err)
	}
	defer rows.Close()

	history := make([]*models.BrigadeStatusHistory, 0)
	for rows.Next() {
		item, err := scanBrigadeStatusHistory(rows)
		if err != nil {
			return nil, fmt.Errorf("repo: GetBrigadeStatusHistory: scan: %w", err)
		}
		history = append(history, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: GetBrigadeStatusHistory: rows: %w", err)
	}

	return &models.GetBrigadeStatusHistoryResult{History: history, Total: total}, nil
}

func (b *BrigadeRepoStruct) GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error) {
	findInput := &models.FindBrigadesByPointInput{
		DepartmentID:     in.DepartmentID,
		OnlyAvailable:    true,
		RequiredSkillIDs: in.RequiredSkillIDs,
		RequiredRoles:    in.RequiredRoles,
		Limit:            in.Limit,
		Offset:           in.Offset,
	}

	if in.Longitude != nil && in.Latitude != nil {
		findInput.Longitude = *in.Longitude
		findInput.Latitude = *in.Latitude
		result, err := NewZoneRepo(b.writePool, b.readPool).FindBrigadesByPoint(ctx, findInput)
		if err != nil {
			return nil, err
		}
		return &models.GetAvailableBrigadesResult{
			Brigades: result.Brigades,
			Total:    result.Total,
		}, nil
	}

	result, err := NewZoneRepo(b.writePool, b.readPool).listAvailableBrigades(ctx, in.DepartmentID, in.RequiredSkillIDs, in.RequiredRoles, in.Limit, in.Offset)
	if err != nil {
		return nil, fmt.Errorf("repo: GetAvailableBrigades: %w", err)
	}

	return result, nil
}

func (b *BrigadeRepoStruct) CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error) {
	reasons := make([]string, 0)

	brigade, err := b.GetBrigadeByID(ctx, &models.GetBrigadeByIDInput{ID: in.BrigadeID})
	if err != nil {
		return nil, fmt.Errorf("repo: CheckBrigadeCanHandleTicket: get brigade: %w", err)
	}

	if brigade.Brigade.DepartmentID != in.DepartmentID {
		reasons = append(reasons, "brigade belongs to another department")
	}
	if brigade.Brigade.Status != models.BrigadeStatusAvailable {
		reasons = append(reasons, "brigade is not available")
	}

	readinessReasons, err := b.CheckBrigadeReadiness(ctx, in.BrigadeID, true, in.RequiredRoles)
	if err != nil {
		return nil, fmt.Errorf("repo: CheckBrigadeCanHandleTicket: check readiness: %w", err)
	}
	reasons = append(reasons, readinessReasons...)

	covers, err := NewZoneRepo(b.writePool, b.readPool).CheckBrigadeCoversPoint(ctx, &models.CheckBrigadeCoversPointInput{
		BrigadeID: in.BrigadeID,
		Longitude: in.Longitude,
		Latitude:  in.Latitude,
	})
	if err != nil {
		return nil, fmt.Errorf("repo: CheckBrigadeCanHandleTicket: check zone: %w", err)
	}
	if !covers.Covers {
		reasons = append(reasons, "brigade does not cover ticket location")
	}

	hasSkills, err := NewSkillRepo(b.writePool, b.readPool).brigadeHasSkills(ctx, in.BrigadeID, in.RequiredSkillIDs)
	if err != nil {
		return nil, fmt.Errorf("repo: CheckBrigadeCanHandleTicket: check skills: %w", err)
	}
	if !hasSkills {
		reasons = append(reasons, "brigade does not have required skills")
	}

	hasMemberSkills, err := b.brigadeHasAvailableMemberSkills(ctx, in.BrigadeID, in.RequiredSkillIDs)
	if err != nil {
		return nil, fmt.Errorf("repo: CheckBrigadeCanHandleTicket: check member skills: %w", err)
	}
	if !hasMemberSkills {
		reasons = append(reasons, "available brigade members do not have required verified skills")
	}

	return &models.CheckBrigadeCanHandleTicketResult{
		CanHandle: len(reasons) == 0,
		Reasons:   reasons,
	}, nil
}

func (b *BrigadeRepoStruct) brigadeHasAvailableMemberSkills(ctx context.Context, brigadeID uuid.UUID, requiredSkillIDs []uuid.UUID) (bool, error) {
	if len(requiredSkillIDs) == 0 {
		return true, nil
	}
	const query = `
		SELECT COUNT(DISTINCT bms.skill_id)
		FROM brigade_member_skills bms
		JOIN brigade_members bm ON bm.id = bms.member_id
		WHERE bms.brigade_id = $1
		  AND bms.skill_id = ANY($2)
		  AND bms.active = true
		  AND bms.work_profile_active = true
		  AND (bms.valid_until IS NULL OR bms.valid_until > now())
		  AND bm.active = true
		  AND bm.availability_status = 'AVAILABLE'
	`
	var count int
	if err := b.readPool.QueryRow(ctx, query, brigadeID, requiredSkillIDs).Scan(&count); err != nil {
		return false, err
	}
	return count == len(requiredSkillIDs), nil
}

func (b *BrigadeRepoStruct) CheckBrigadeReadiness(ctx context.Context, brigadeID uuid.UUID, requireOnShift bool, requiredRoles []models.BrigadeMemberRole) ([]string, error) {
	reasons := make([]string, 0)

	hasActiveMembers, err := b.brigadeHasActiveMembers(ctx, brigadeID)
	if err != nil {
		return nil, fmt.Errorf("check active members: %w", err)
	}
	if !hasActiveMembers {
		reasons = append(reasons, "brigade has no active members")
	}

	if requireOnShift {
		hasAvailableMembers, err := b.brigadeHasAvailableActiveMembers(ctx, brigadeID)
		if err != nil {
			return nil, fmt.Errorf("check available active members: %w", err)
		}
		if !hasAvailableMembers {
			reasons = append(reasons, "brigade has no available active members")
		}

		onShift, err := b.brigadeIsOnShift(ctx, brigadeID)
		if err != nil {
			return nil, fmt.Errorf("check shift: %w", err)
		}
		if !onShift {
			reasons = append(reasons, "brigade is not on shift")
		}
	}

	hasRoles, err := b.brigadeHasRoles(ctx, brigadeID, requiredRoles)
	if err != nil {
		return nil, fmt.Errorf("check roles: %w", err)
	}
	if !hasRoles {
		reasons = append(reasons, "brigade does not have required roles")
	}

	return reasons, nil
}

func (b *BrigadeRepoStruct) brigadeHasActiveMembers(ctx context.Context, brigadeID uuid.UUID) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM brigade_members
			WHERE brigade_id = $1
			  AND active = true
		)
	`

	var exists bool
	if err := b.readPool.QueryRow(ctx, query, brigadeID).Scan(&exists); err != nil {
		return false, err
	}

	return exists, nil
}

func (b *BrigadeRepoStruct) brigadeHasAvailableActiveMembers(ctx context.Context, brigadeID uuid.UUID) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM brigade_members
			WHERE brigade_id = $1
			  AND active = true
			  AND availability_status = $2
		)
	`

	var exists bool
	if err := b.readPool.QueryRow(ctx, query, brigadeID, string(models.BrigadeMemberAvailabilityAvailable)).Scan(&exists); err != nil {
		return false, err
	}

	return exists, nil
}

func (b *BrigadeRepoStruct) brigadeIsOnShift(ctx context.Context, brigadeID uuid.UUID) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM brigade_schedule
			WHERE brigade_id = $1
			  AND active = true
			  AND (valid_from IS NULL OR (now() AT TIME ZONE timezone)::date >= valid_from)
			  AND (valid_to IS NULL OR (now() AT TIME ZONE timezone)::date <= valid_to)
			  AND EXTRACT(ISODOW FROM now() AT TIME ZONE timezone)::int = day_of_week
			  AND (
				(starts_at < ends_at AND (now() AT TIME ZONE timezone)::time >= starts_at AND (now() AT TIME ZONE timezone)::time < ends_at)
				OR
				(starts_at > ends_at AND ((now() AT TIME ZONE timezone)::time >= starts_at OR (now() AT TIME ZONE timezone)::time < ends_at))
			  )
		)
	`

	var exists bool
	if err := b.readPool.QueryRow(ctx, query, brigadeID).Scan(&exists); err != nil {
		return false, err
	}

	return exists, nil
}

func (b *BrigadeRepoStruct) brigadeHasRoles(ctx context.Context, brigadeID uuid.UUID, requiredRoles []models.BrigadeMemberRole) (bool, error) {
	if len(requiredRoles) == 0 {
		return true, nil
	}

	const query = `
		SELECT COUNT(DISTINCT role)
		FROM brigade_members
		WHERE brigade_id = $1
		  AND active = true
		  AND role = ANY($2)
	`

	var count int
	if err := b.readPool.QueryRow(ctx, query, brigadeID, roleStrings(requiredRoles)).Scan(&count); err != nil {
		return false, err
	}

	return count == len(requiredRoles), nil
}

func scanBrigade(row scanner) (*models.Brigade, error) {
	var brigade models.Brigade
	var specialization sql.NullString
	var deactivatedAt sql.NullTime
	var archivedAt sql.NullTime

	err := row.Scan(
		&brigade.ID,
		&brigade.DepartmentID,
		&brigade.Name,
		&brigade.Description,
		&brigade.Status,
		&specialization,
		&brigade.CreatedAt,
		&brigade.UpdatedAt,
		&deactivatedAt,
		&archivedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}

		return nil, err
	}

	if specialization.Valid {
		brigade.Specialization = &specialization.String
	}
	if deactivatedAt.Valid {
		brigade.DeactivatedAt = &deactivatedAt.Time
	}
	if archivedAt.Valid {
		brigade.ArchivedAt = &archivedAt.Time
	}

	return &brigade, nil
}

func (b *BrigadeRepoStruct) setBrigadeStatusWithTx(
	ctx context.Context,
	brigadeID uuid.UUID,
	status models.BrigadeStatus,
	reason string,
	changedBy *uuid.UUID,
	requestID *string,
	traceID *string,
	setDeactivatedAt bool,
	setArchivedAt bool,
) (*models.Brigade, error) {
	tx, err := b.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	current, err := b.getBrigadeByIDForUpdate(ctx, tx, brigadeID)
	if err != nil {
		return nil, fmt.Errorf("get current brigade: %w", err)
	}

	query := `
		UPDATE brigades
		SET
			status = $1,
			updated_at = now(),
			deactivated_at = CASE WHEN $2 THEN now() ELSE deactivated_at END,
			archived_at = CASE WHEN $3 THEN now() ELSE archived_at END
		WHERE id = $4
		RETURNING
			id,
			department_id,
			name,
			description,
			status,
			specialization,
			created_at,
			updated_at,
			deactivated_at,
			archived_at
	`

	brigade, err := scanBrigade(tx.QueryRow(ctx, query, string(status), setDeactivatedAt, setArchivedAt, brigadeID))
	if err != nil {
		return nil, fmt.Errorf("update brigade status: %w", err)
	}

	if err = b.insertBrigadeStatusHistory(ctx, tx, brigadeID, &current.Status, status, reason, changedBy, requestID); err != nil {
		return nil, fmt.Errorf("insert status history: %w", err)
	}

	payload := map[string]any{
		"event_id":      uuid.NewString(),
		"event_type":    "BrigadeStatusChanged",
		"brigade_id":    brigade.ID.String(),
		"department_id": brigade.DepartmentID.String(),
		"from_status":   current.Status,
		"to_status":     brigade.Status,
		"reason":        reason,
		"changed_at":    brigade.UpdatedAt,
	}
	if changedBy != nil {
		payload["changed_by_user_id"] = changedBy.String()
	}

	eventType := "BrigadeStatusChanged"
	if status == models.BrigadeStatusInactive && setDeactivatedAt {
		eventType = "BrigadeDeactivated"
		payload["event_type"] = eventType
	}
	if status == models.BrigadeStatusArchived {
		eventType = "BrigadeArchived"
		payload["event_type"] = eventType
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", brigade.ID, eventType, payload, requestID, traceID); err != nil {
		return nil, fmt.Errorf("insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return brigade, nil
}

func (b *BrigadeRepoStruct) getBrigadeByIDForUpdate(ctx context.Context, tx pgx.Tx, brigadeID uuid.UUID) (*models.Brigade, error) {
	const query = `
		SELECT
			id,
			department_id,
			name,
			description,
			status,
			specialization,
			created_at,
			updated_at,
			deactivated_at,
			archived_at
		FROM brigades
		WHERE id = $1
		FOR UPDATE
	`

	return scanBrigade(tx.QueryRow(ctx, query, brigadeID))
}

func (b *BrigadeRepoStruct) insertBrigadeStatusHistory(
	ctx context.Context,
	tx pgx.Tx,
	brigadeID uuid.UUID,
	fromStatus *models.BrigadeStatus,
	toStatus models.BrigadeStatus,
	reason string,
	changedBy *uuid.UUID,
	requestID *string,
) error {
	const query = `
		INSERT INTO brigade_status_history (
			brigade_id,
			from_status,
			to_status,
			reason,
			changed_by_user_id,
			request_id
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	var fromStatusValue *string
	if fromStatus != nil {
		value := string(*fromStatus)
		fromStatusValue = &value
	}

	_, err := tx.Exec(ctx, query, brigadeID, fromStatusValue, string(toStatus), reason, changedBy, requestID)
	return err
}

func scanBrigadeStatusHistory(row scanner) (*models.BrigadeStatusHistory, error) {
	var item models.BrigadeStatusHistory
	var fromStatus sql.NullString
	var changedBy sql.NullString
	var requestID sql.NullString

	err := row.Scan(
		&item.ID,
		&item.BrigadeID,
		&fromStatus,
		&item.ToStatus,
		&item.Reason,
		&changedBy,
		&requestID,
		&item.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if fromStatus.Valid {
		value := models.BrigadeStatus(fromStatus.String)
		item.FromStatus = &value
	}
	if changedBy.Valid {
		id, err := uuid.Parse(changedBy.String)
		if err != nil {
			return nil, fmt.Errorf("parse changed_by_user_id: %w", err)
		}
		item.ChangedByUserID = &id
	}
	if requestID.Valid {
		item.RequestID = &requestID.String
	}

	return &item, nil
}

func insertOutboxEvent(
	ctx context.Context,
	tx pgx.Tx,
	aggregateType string,
	aggregateID uuid.UUID,
	eventType string,
	payload any,
	requestID *string,
	traceID *string,
) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	const query = `
		INSERT INTO outbox_events (
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			request_id,
			trace_id
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err = tx.Exec(
		ctx,
		query,
		aggregateType,
		aggregateID,
		eventType,
		payloadBytes,
		requestID,
		traceID,
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	return nil
}

func brigadeSortBy(srtBy models.BrigadeSortBy) string {
	switch srtBy {
	case models.BrigadeSortByCreatedAt:
		return "created_at"
	case models.BrigadeSortByUpdatedAt:
		return "updated_at"
	case models.BrigadeSortByName:
		return "name"
	case models.BrigadeSortByStatus:
		return "status"
	default:
		return "created_at"
	}
}

func brigadeSortOrder(order models.SortOrder) string {
	switch order {
	case models.SortOrderDesc:
		return "DESC"
	case models.SortOrderAsc:
		return "ASC"
	default:
		return "DESC"
	}
}

func uuidStrings(ids []uuid.UUID) []string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, id.String())
	}
	return values
}

func roleStrings(roles []models.BrigadeMemberRole) []string {
	values := make([]string, 0, len(roles))
	for _, role := range roles {
		values = append(values, string(role))
	}
	return values
}

func isBrigadeNameUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName == "" || pgErr.ConstraintName == "brigades_department_name_active_uidx"
	}

	return false
}
