package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"profile/models"
	profilepkg "profile/pkg"
)

type WorkProfileRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

var _ WorkProfileRepository = (*WorkProfileRepoStruct)(nil)

func NewWorkProfileRepository(writePool *pgxpool.Pool, readPool *pgxpool.Pool) *WorkProfileRepoStruct {
	if readPool == nil {
		readPool = writePool
	}
	return &WorkProfileRepoStruct{writePool: writePool, readPool: readPool}
}

func (w *WorkProfileRepoStruct) CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error) {
	tx, err := beginCommandTx(ctx, w.writePool)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateWorkProfile(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		INSERT INTO work_profiles (
			user_profile_id,
			department_id,
			employee_number,
			position,
			status
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`

	var workProfileID uuid.UUID
	err = tx.QueryRow(
		ctx,
		query,
		in.UserProfileID,
		in.DepartmentID,
		trimOptionalString(in.EmployeeNumber),
		strings.TrimSpace(in.Position),
		models.WorkProfileStatusActive,
	).Scan(&workProfileID)
	if err != nil {
		return nil, mapDatabaseError("CreateWorkProfile()", err)
	}

	if err = insertWorkProfileStatusHistory(
		ctx,
		tx,
		workProfileID,
		nil,
		models.WorkProfileStatusActive,
		"work profile created",
		in.ActorUserID,
	); err != nil {
		return nil, fmt.Errorf("repository: CreateWorkProfile(): insert status history: %w", err)
	}

	details, err := getWorkProfileDetailsByID(ctx, tx, workProfileID, false)
	if err != nil {
		return nil, mapDatabaseError("CreateWorkProfile(): get details", err)
	}

	if err = insertOutboxEvent(ctx, tx, "work_profile", workProfileID, "WorkProfileCreated", in.ActorUserID, details); err != nil {
		return nil, fmt.Errorf("repository: CreateWorkProfile(): insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: CreateWorkProfile(): commit: %w", err)
	}

	return &models.CreateWorkProfileResult{Details: details}, nil
}

func (w *WorkProfileRepoStruct) UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error) {
	tx, err := beginCommandTx(ctx, w.writePool)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateWorkProfile(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE work_profiles
		SET
			employee_number = CASE WHEN $2 THEN NULL ELSE COALESCE($1, employee_number) END,
			position = COALESCE($3, position),
			updated_at = now()
		WHERE id = $4
		RETURNING id
	`

	var workProfileID uuid.UUID
	err = tx.QueryRow(
		ctx,
		query,
		trimOptionalString(in.EmployeeNumber),
		in.ClearEmployeeNumber,
		trimOptionalString(in.Position),
		in.ID,
	).Scan(&workProfileID)
	if err != nil {
		return nil, mapDatabaseError("UpdateWorkProfile()", err)
	}

	details, err := getWorkProfileDetailsByID(ctx, tx, workProfileID, false)
	if err != nil {
		return nil, mapDatabaseError("UpdateWorkProfile(): get details", err)
	}

	if err = insertOutboxEvent(ctx, tx, "work_profile", workProfileID, "WorkProfileUpdated", in.ActorUserID, details); err != nil {
		return nil, fmt.Errorf("repository: UpdateWorkProfile(): insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: UpdateWorkProfile(): commit: %w", err)
	}

	return &models.UpdateWorkProfileResult{Details: details}, nil
}

func (w *WorkProfileRepoStruct) GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error) {
	details, err := getWorkProfileDetailsByID(ctx, w.readPool, in.ID, false)
	if err != nil {
		return nil, mapDatabaseError("GetWorkProfileByID()", err)
	}
	return &models.GetWorkProfileByIDResult{Details: details}, nil
}

func (w *WorkProfileRepoStruct) GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error) {
	const query = `
		SELECT
			wp.id, wp.user_profile_id, wp.department_id, wp.employee_number,
			wp.position, wp.status, wp.deactivated_at, wp.created_at, wp.updated_at,
			up.id, up.user_id, up.full_name, up.phone, up.avatar_file_id,
			up.preferred_contact_method, up.created_at, up.updated_at
		FROM work_profiles wp
		JOIN user_profiles up ON up.id = wp.user_profile_id
		WHERE up.user_id = $1
	`

	details, err := scanWorkProfileDetails(w.readPool.QueryRow(ctx, query, in.UserID))
	if err != nil {
		return nil, mapDatabaseError("GetWorkProfileByUserID()", err)
	}
	return &models.GetWorkProfileByUserIDResult{Details: details}, nil
}

func (w *WorkProfileRepoStruct) ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error) {
	whereParts := make([]string, 0, 3)
	args := make([]any, 0, 5)
	addWhere := func(condition string, value any) {
		args = append(args, value)
		whereParts = append(whereParts, fmt.Sprintf(condition, len(args)))
	}

	if in.DepartmentID != nil {
		addWhere("wp.department_id = $%d", *in.DepartmentID)
	}
	if in.Status != nil {
		addWhere("wp.status = $%d", *in.Status)
	}
	if in.Query != nil {
		addWhere("(up.full_name ILIKE $%[1]d OR wp.position ILIKE $%[1]d OR wp.employee_number ILIKE $%[1]d)", "%"+strings.TrimSpace(*in.Query)+"%")
	}

	whereSQL := ""
	if len(whereParts) > 0 {
		whereSQL = "WHERE " + strings.Join(whereParts, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM work_profiles wp
		JOIN user_profiles up ON up.id = wp.user_profile_id
		%s
	`, whereSQL)
	var total int64
	if err := w.readPool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, mapDatabaseError("ListWorkProfiles(): count", err)
	}

	args = append(args, in.Limit, in.Offset)
	query := fmt.Sprintf(`
		SELECT
			wp.id, wp.user_profile_id, wp.department_id, wp.employee_number,
			wp.position, wp.status, wp.deactivated_at, wp.created_at, wp.updated_at,
			up.id, up.user_id, up.full_name, up.phone, up.avatar_file_id,
			up.preferred_contact_method, up.created_at, up.updated_at
		FROM work_profiles wp
		JOIN user_profiles up ON up.id = wp.user_profile_id
		%s
		ORDER BY %s %s, wp.id ASC
		LIMIT $%d OFFSET $%d
	`, whereSQL, workProfileSortColumn(in.SortBy), sortOrderSQL(in.SortOrder), len(args)-1, len(args))

	rows, err := w.readPool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapDatabaseError("ListWorkProfiles(): query", err)
	}
	defer rows.Close()

	profiles := make([]*models.WorkProfileDetails, 0)
	for rows.Next() {
		details, scanErr := scanWorkProfileDetails(rows)
		if scanErr != nil {
			return nil, mapDatabaseError("ListWorkProfiles(): scan", scanErr)
		}
		profiles = append(profiles, details)
	}
	if err = rows.Err(); err != nil {
		return nil, mapDatabaseError("ListWorkProfiles(): rows", err)
	}

	return &models.ListWorkProfilesResult{WorkProfiles: profiles, Total: total}, nil
}

func (w *WorkProfileRepoStruct) DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error) {
	tx, err := beginCommandTx(ctx, w.writePool)
	if err != nil {
		return nil, fmt.Errorf("repository: DeactivateWorkProfile(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	current, err := getWorkProfileDetailsByID(ctx, tx, in.ID, true)
	if err != nil {
		return nil, mapDatabaseError("DeactivateWorkProfile(): get profile", err)
	}
	if current.WorkProfile.Status == models.WorkProfileStatusInactive {
		if err = tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("repository: DeactivateWorkProfile(): commit no-op: %w", err)
		}
		return &models.DeactivateWorkProfileResult{Details: current}, nil
	}

	fromStatus := current.WorkProfile.Status
	const query = `
		UPDATE work_profiles
		SET status = $1, deactivated_at = now(), updated_at = now()
		WHERE id = $2
	`
	if _, err = tx.Exec(ctx, query, models.WorkProfileStatusInactive, in.ID); err != nil {
		return nil, mapDatabaseError("DeactivateWorkProfile(): update", err)
	}

	if err = insertWorkProfileStatusHistory(ctx, tx, in.ID, &fromStatus, models.WorkProfileStatusInactive, in.Reason, in.ActorUserID); err != nil {
		return nil, fmt.Errorf("repository: DeactivateWorkProfile(): insert status history: %w", err)
	}

	details, err := getWorkProfileDetailsByID(ctx, tx, in.ID, false)
	if err != nil {
		return nil, mapDatabaseError("DeactivateWorkProfile(): get updated profile", err)
	}
	payload := map[string]any{"from_status": fromStatus, "to_status": models.WorkProfileStatusInactive, "reason": in.Reason, "profile": details}
	if err = insertOutboxEvent(ctx, tx, "work_profile", in.ID, "WorkProfileDeactivated", in.ActorUserID, payload); err != nil {
		return nil, fmt.Errorf("repository: DeactivateWorkProfile(): insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: DeactivateWorkProfile(): commit: %w", err)
	}
	return &models.DeactivateWorkProfileResult{Details: details}, nil
}

func (w *WorkProfileRepoStruct) ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error) {
	tx, err := beginCommandTx(ctx, w.writePool)
	if err != nil {
		return nil, fmt.Errorf("repository: ChangeWorkProfileDepartment(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	current, err := getWorkProfileDetailsByID(ctx, tx, in.ID, true)
	if err != nil {
		return nil, mapDatabaseError("ChangeWorkProfileDepartment(): get profile", err)
	}
	oldDepartmentID := current.WorkProfile.DepartmentID
	if oldDepartmentID == in.DepartmentID {
		if err = tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("repository: ChangeWorkProfileDepartment(): commit no-op: %w", err)
		}
		return &models.ChangeWorkProfileDepartmentResult{Details: current}, nil
	}

	const query = `UPDATE work_profiles SET department_id = $1, updated_at = now() WHERE id = $2`
	if _, err = tx.Exec(ctx, query, in.DepartmentID, in.ID); err != nil {
		return nil, mapDatabaseError("ChangeWorkProfileDepartment(): update", err)
	}
	details, err := getWorkProfileDetailsByID(ctx, tx, in.ID, false)
	if err != nil {
		return nil, mapDatabaseError("ChangeWorkProfileDepartment(): get updated profile", err)
	}
	payload := map[string]any{"old_department_id": oldDepartmentID, "new_department_id": in.DepartmentID, "reason": in.Reason, "profile": details}
	if err = insertOutboxEvent(ctx, tx, "work_profile", in.ID, "WorkProfileDepartmentChanged", in.ActorUserID, payload); err != nil {
		return nil, fmt.Errorf("repository: ChangeWorkProfileDepartment(): insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: ChangeWorkProfileDepartment(): commit: %w", err)
	}
	return &models.ChangeWorkProfileDepartmentResult{Details: details}, nil
}

func (w *WorkProfileRepoStruct) SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error) {
	tx, err := beginCommandTx(ctx, w.writePool)
	if err != nil {
		return nil, fmt.Errorf("repository: SetWorkProfileStatus(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	current, err := getWorkProfileDetailsByID(ctx, tx, in.ID, true)
	if err != nil {
		return nil, mapDatabaseError("SetWorkProfileStatus(): get profile", err)
	}
	fromStatus := current.WorkProfile.Status
	if fromStatus == in.Status {
		if err = tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("repository: SetWorkProfileStatus(): commit no-op: %w", err)
		}
		return &models.SetWorkProfileStatusResult{Details: current}, nil
	}

	const query = `
		UPDATE work_profiles
		SET
			status = $1::varchar,
			deactivated_at = CASE WHEN $1::varchar = 'INACTIVE' THEN now() ELSE NULL END,
			updated_at = now()
		WHERE id = $2
	`
	if _, err = tx.Exec(ctx, query, in.Status, in.ID); err != nil {
		return nil, mapDatabaseError("SetWorkProfileStatus(): update", err)
	}
	if err = insertWorkProfileStatusHistory(ctx, tx, in.ID, &fromStatus, in.Status, in.Reason, in.ActorUserID); err != nil {
		return nil, fmt.Errorf("repository: SetWorkProfileStatus(): insert status history: %w", err)
	}

	details, err := getWorkProfileDetailsByID(ctx, tx, in.ID, false)
	if err != nil {
		return nil, mapDatabaseError("SetWorkProfileStatus(): get updated profile", err)
	}
	payload := map[string]any{"from_status": fromStatus, "to_status": in.Status, "reason": in.Reason, "profile": details}
	if err = insertOutboxEvent(ctx, tx, "work_profile", in.ID, "WorkProfileStatusChanged", in.ActorUserID, payload); err != nil {
		return nil, fmt.Errorf("repository: SetWorkProfileStatus(): insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: SetWorkProfileStatus(): commit: %w", err)
	}
	return &models.SetWorkProfileStatusResult{Details: details}, nil
}

func (w *WorkProfileRepoStruct) GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error) {
	const countQuery = `SELECT COUNT(*) FROM work_profile_status_history WHERE work_profile_id = $1`
	var total int64
	if err := w.readPool.QueryRow(ctx, countQuery, in.WorkProfileID).Scan(&total); err != nil {
		return nil, mapDatabaseError("GetWorkProfileStatusHistory(): count", err)
	}

	const query = `
		SELECT id, work_profile_id, from_status, to_status, reason,
		       changed_by_user_id, request_id, created_at
		FROM work_profile_status_history
		WHERE work_profile_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := w.readPool.Query(ctx, query, in.WorkProfileID, in.Limit, in.Offset)
	if err != nil {
		return nil, mapDatabaseError("GetWorkProfileStatusHistory(): query", err)
	}
	defer rows.Close()

	history := make([]*models.WorkProfileStatusHistory, 0)
	for rows.Next() {
		item, scanErr := scanWorkProfileStatusHistory(rows)
		if scanErr != nil {
			return nil, mapDatabaseError("GetWorkProfileStatusHistory(): scan", scanErr)
		}
		history = append(history, item)
	}
	if err = rows.Err(); err != nil {
		return nil, mapDatabaseError("GetWorkProfileStatusHistory(): rows", err)
	}

	return &models.GetWorkProfileStatusHistoryResult{History: history, Total: total}, nil
}

func (w *WorkProfileRepoStruct) ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error) {
	const query = `
		SELECT up.id, wp.id, up.user_id, wp.department_id, wp.status
		FROM user_profiles up
		JOIN work_profiles wp ON wp.user_profile_id = up.id
		WHERE up.user_id = $1
	`

	result := &models.ResolveWorkingDepartmentResult{}
	err := w.readPool.QueryRow(ctx, query, in.UserID).Scan(
		&result.UserProfileID,
		&result.WorkProfileID,
		&result.UserID,
		&result.DepartmentID,
		&result.WorkProfileStatus,
	)
	if err != nil {
		return nil, mapDatabaseError("ResolveWorkingDepartment()", err)
	}
	result.CanOperate = result.WorkProfileStatus == models.WorkProfileStatusActive ||
		result.WorkProfileStatus == models.WorkProfileStatusOnShift
	return result, nil
}

func (w *WorkProfileRepoStruct) CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error) {
	result := &models.CheckProfileCanJoinBrigadeResult{
		Allowed: false,
		Reason:  models.CanJoinBrigadeReasonNoWorkProfile,
	}

	var workProfileID *uuid.UUID
	var departmentID *uuid.UUID
	var status *models.WorkProfileStatus

	if in.UserID != nil {
		const query = `
			SELECT up.id, up.user_id, wp.id, wp.department_id, wp.status
			FROM user_profiles up
			LEFT JOIN work_profiles wp ON wp.user_profile_id = up.id
			WHERE up.user_id = $1
		`
		err := w.readPool.QueryRow(ctx, query, *in.UserID).Scan(
			&result.UserProfileID,
			&result.UserID,
			&workProfileID,
			&departmentID,
			&status,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return result, nil
			}
			return nil, mapDatabaseError("CheckProfileCanJoinBrigade()", err)
		}
	} else {
		const query = `
			SELECT up.id, up.user_id, wp.id, wp.department_id, wp.status
			FROM work_profiles wp
			JOIN user_profiles up ON up.id = wp.user_profile_id
			WHERE wp.id = $1
		`
		err := w.readPool.QueryRow(ctx, query, *in.WorkProfileID).Scan(
			&result.UserProfileID,
			&result.UserID,
			&workProfileID,
			&departmentID,
			&status,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return result, nil
			}
			return nil, mapDatabaseError("CheckProfileCanJoinBrigade()", err)
		}
	}

	if workProfileID == nil || departmentID == nil || status == nil {
		return result, nil
	}
	result.WorkProfileID = *workProfileID
	result.DepartmentID = *departmentID
	result.Allowed, result.Reason = evaluateCanJoinBrigade(*status, *departmentID, in.BrigadeDepartmentID)
	return result, nil
}

func getWorkProfileDetailsByID(ctx context.Context, q Querier, id uuid.UUID, forUpdate bool) (*models.WorkProfileDetails, error) {
	lockSQL := ""
	if forUpdate {
		lockSQL = "FOR UPDATE OF wp"
	}
	query := fmt.Sprintf(`
		SELECT
			wp.id, wp.user_profile_id, wp.department_id, wp.employee_number,
			wp.position, wp.status, wp.deactivated_at, wp.created_at, wp.updated_at,
			up.id, up.user_id, up.full_name, up.phone, up.avatar_file_id,
			up.preferred_contact_method, up.created_at, up.updated_at
		FROM work_profiles wp
		JOIN user_profiles up ON up.id = wp.user_profile_id
		WHERE wp.id = $1
		%s
	`, lockSQL)
	return scanWorkProfileDetails(q.QueryRow(ctx, query, id))
}

func insertWorkProfileStatusHistory(
	ctx context.Context,
	q Querier,
	workProfileID uuid.UUID,
	fromStatus *models.WorkProfileStatus,
	toStatus models.WorkProfileStatus,
	reason string,
	actorUserID *uuid.UUID,
) error {
	var requestID *string
	if value, ok := profilepkg.RequestIDFromContext(ctx); ok {
		requestID = &value
	}
	const query = `
		INSERT INTO work_profile_status_history (
			work_profile_id, from_status, to_status, reason,
			changed_by_user_id, request_id
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := q.Exec(ctx, query, workProfileID, fromStatus, toStatus, strings.TrimSpace(reason), actorUserID, requestID)
	return err
}

func scanWorkProfileDetails(s scanner) (*models.WorkProfileDetails, error) {
	workProfile := &models.WorkProfile{}
	userProfile := &models.UserProfile{}
	err := s.Scan(
		&workProfile.ID,
		&workProfile.UserProfileID,
		&workProfile.DepartmentID,
		&workProfile.EmployeeNumber,
		&workProfile.Position,
		&workProfile.Status,
		&workProfile.DeactivatedAt,
		&workProfile.CreatedAt,
		&workProfile.UpdatedAt,
		&userProfile.ID,
		&userProfile.UserID,
		&userProfile.FullName,
		&userProfile.Phone,
		&userProfile.AvatarFileID,
		&userProfile.PreferredContactMethod,
		&userProfile.CreatedAt,
		&userProfile.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &models.WorkProfileDetails{WorkProfile: workProfile, UserProfile: userProfile}, nil
}

func scanWorkProfileStatusHistory(s scanner) (*models.WorkProfileStatusHistory, error) {
	item := &models.WorkProfileStatusHistory{}
	var fromStatus *string
	err := s.Scan(
		&item.ID,
		&item.WorkProfileID,
		&fromStatus,
		&item.ToStatus,
		&item.Reason,
		&item.ChangedByUserID,
		&item.RequestID,
		&item.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if fromStatus != nil {
		status := models.WorkProfileStatus(*fromStatus)
		item.FromStatus = &status
	}
	return item, nil
}

func workProfileSortColumn(sortBy models.WorkProfileSortBy) string {
	switch sortBy {
	case models.WorkProfileSortByUpdatedAt:
		return "wp.updated_at"
	case models.WorkProfileSortByFullName:
		return "up.full_name"
	case models.WorkProfileSortByPosition:
		return "wp.position"
	case models.WorkProfileSortByStatus:
		return "wp.status"
	case models.WorkProfileSortByEmployeeNumber:
		return "wp.employee_number"
	default:
		return "wp.created_at"
	}
}

func evaluateCanJoinBrigade(status models.WorkProfileStatus, departmentID uuid.UUID, brigadeDepartmentID uuid.UUID) (bool, models.CanJoinBrigadeReason) {
	switch status {
	case models.WorkProfileStatusInactive:
		return false, models.CanJoinBrigadeReasonProfileInactive
	case models.WorkProfileStatusSuspended:
		return false, models.CanJoinBrigadeReasonProfileSuspended
	case models.WorkProfileStatusOffShift:
		return false, models.CanJoinBrigadeReasonProfileOffShift
	}
	if departmentID != brigadeDepartmentID {
		return false, models.CanJoinBrigadeReasonDepartmentMismatch
	}
	return true, models.CanJoinBrigadeReasonAllowed
}
