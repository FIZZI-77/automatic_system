package repository

import (
	"brigade/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type MemberRepoStruct struct {
	db *sql.DB
}

func NewMemberRepo(db *sql.DB) *MemberRepoStruct {
	return &MemberRepoStruct{db: db}
}

func (m *MemberRepoStruct) AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repo: AddBrigadeMember: begin tx: %w", err)
	}
	defer tx.Rollback()

	member, err := m.insertBrigadeMember(ctx, tx, in)
	if err != nil {
		if isMemberUniqueViolation(err) {
			return nil, fmt.Errorf("repo: AddBrigadeMember: %w", models.ErrAlreadyExists)
		}
		return nil, fmt.Errorf("repo: AddBrigadeMember: insert member: %w", err)
	}

	if err = m.insertBrigadeMemberHistory(ctx, tx, member, models.BrigadeMemberHistoryActionAdded, nil, &member.Role, in.ChangedByUserID, in.RequestID); err != nil {
		return nil, fmt.Errorf("repo: AddBrigadeMember: insert history: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeMemberAdded",
		"brigade_id": member.BrigadeID.String(),
		"member_id":  member.ID.String(),
		"user_id":    member.UserID.String(),
		"role":       member.Role,
		"created_at": member.CreatedAt,
	}
	if member.ProfileID != nil {
		payload["profile_id"] = member.ProfileID.String()
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", member.BrigadeID, "BrigadeMemberAdded", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: AddBrigadeMember: insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repo: AddBrigadeMember: commit tx: %w", err)
	}

	return &models.AddBrigadeMemberResult{Member: member}, nil
}

func (m *MemberRepoStruct) insertBrigadeMember(ctx context.Context, tx *sql.Tx, in *models.AddBrigadeMemberInput) (*models.BrigadeMember, error) {
	const query = `
		INSERT INTO brigade_members (
			brigade_id,
			user_id,
			profile_id,
			role
		)
		VALUES ($1, $2, $3, $4)
		RETURNING
			id,
			brigade_id,
			user_id,
			profile_id,
			role,
			active,
			availability_status,
			availability_status_changed_at,
			joined_at,
			left_at,
			created_at,
			updated_at
	`

	return scanBrigadeMember(tx.QueryRowContext(ctx, query, in.BrigadeID, in.UserID, in.ProfileID, string(in.Role)))
}

func (m *MemberRepoStruct) RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeMember: begin tx: %w", err)
	}
	defer tx.Rollback()

	member, err := m.getBrigadeMemberByIDForUpdate(ctx, tx, in.BrigadeID, in.MemberID)
	if err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeMember: get member: %w", err)
	}

	const query = `
		UPDATE brigade_members
		SET
			active = false,
			left_at = now(),
			updated_at = now()
		WHERE id = $1 AND brigade_id = $2
		RETURNING
			id,
			brigade_id,
			user_id,
			profile_id,
			role,
			active,
			availability_status,
			availability_status_changed_at,
			joined_at,
			left_at,
			created_at,
			updated_at
	`

	removed, err := scanBrigadeMember(tx.QueryRowContext(ctx, query, in.MemberID, in.BrigadeID))
	if err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeMember: update member: %w", err)
	}

	if err = m.insertBrigadeMemberHistory(ctx, tx, member, models.BrigadeMemberHistoryActionRemoved, &member.Role, nil, in.ChangedByUserID, in.RequestID); err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeMember: insert history: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeMemberRemoved",
		"brigade_id": removed.BrigadeID.String(),
		"member_id":  removed.ID.String(),
		"user_id":    removed.UserID.String(),
		"role":       removed.Role,
		"reason":     in.Reason,
		"left_at":    removed.LeftAt,
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", removed.BrigadeID, "BrigadeMemberRemoved", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeMember: insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repo: RemoveBrigadeMember: commit tx: %w", err)
	}

	return &models.RemoveBrigadeMemberResult{Member: removed}, nil
}

func (m *MemberRepoStruct) ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repo: ChangeBrigadeMemberRole: begin tx: %w", err)
	}
	defer tx.Rollback()

	member, err := m.getBrigadeMemberByIDForUpdate(ctx, tx, in.BrigadeID, in.MemberID)
	if err != nil {
		return nil, fmt.Errorf("repo: ChangeBrigadeMemberRole: get member: %w", err)
	}
	oldRole := member.Role

	const query = `
		UPDATE brigade_members
		SET role = $1, updated_at = now()
		WHERE id = $2 AND brigade_id = $3
		RETURNING
			id,
			brigade_id,
			user_id,
			profile_id,
			role,
			active,
			availability_status,
			availability_status_changed_at,
			joined_at,
			left_at,
			created_at,
			updated_at
	`

	updated, err := scanBrigadeMember(tx.QueryRowContext(ctx, query, string(in.Role), in.MemberID, in.BrigadeID))
	if err != nil {
		return nil, fmt.Errorf("repo: ChangeBrigadeMemberRole: update member: %w", err)
	}

	if err = m.insertBrigadeMemberHistory(ctx, tx, updated, models.BrigadeMemberHistoryActionRoleChanged, &oldRole, &updated.Role, in.ChangedByUserID, in.RequestID); err != nil {
		return nil, fmt.Errorf("repo: ChangeBrigadeMemberRole: insert history: %w", err)
	}

	payload := map[string]any{
		"event_id":   uuid.NewString(),
		"event_type": "BrigadeMemberRoleChanged",
		"brigade_id": updated.BrigadeID.String(),
		"member_id":  updated.ID.String(),
		"user_id":    updated.UserID.String(),
		"old_role":   oldRole,
		"new_role":   updated.Role,
		"updated_at": updated.UpdatedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", updated.BrigadeID, "BrigadeMemberRoleChanged", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: ChangeBrigadeMemberRole: insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repo: ChangeBrigadeMemberRole: commit tx: %w", err)
	}

	return &models.ChangeBrigadeMemberRoleResult{Member: updated}, nil
}

func (m *MemberRepoStruct) SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeMemberAvailability: begin tx: %w", err)
	}
	defer tx.Rollback()

	member, err := m.getBrigadeMemberByIDForUpdate(ctx, tx, in.BrigadeID, in.MemberID)
	if err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeMemberAvailability: get member: %w", err)
	}
	oldStatus := member.AvailabilityStatus

	const query = `
		UPDATE brigade_members
		SET
			availability_status = $1,
			availability_status_changed_at = now(),
			updated_at = now()
		WHERE id = $2 AND brigade_id = $3
		RETURNING
			id,
			brigade_id,
			user_id,
			profile_id,
			role,
			active,
			availability_status,
			availability_status_changed_at,
			joined_at,
			left_at,
			created_at,
			updated_at
	`

	updated, err := scanBrigadeMember(tx.QueryRowContext(ctx, query, string(in.Status), in.MemberID, in.BrigadeID))
	if err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeMemberAvailability: update member: %w", err)
	}

	if err = m.insertBrigadeMemberStatusHistory(ctx, tx, updated, &oldStatus, updated.AvailabilityStatus, in.Reason, in.ChangedByUserID, in.RequestID); err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeMemberAvailability: insert history: %w", err)
	}

	payload := map[string]any{
		"event_id":    uuid.NewString(),
		"event_type":  "BrigadeMemberAvailabilityChanged",
		"brigade_id":  updated.BrigadeID.String(),
		"member_id":   updated.ID.String(),
		"user_id":     updated.UserID.String(),
		"from_status": oldStatus,
		"to_status":   updated.AvailabilityStatus,
		"reason":      in.Reason,
		"changed_at":  updated.AvailabilityStatusChangedAt,
	}

	if err = insertOutboxEvent(ctx, tx, "brigade", updated.BrigadeID, "BrigadeMemberAvailabilityChanged", payload, in.RequestID, in.TraceID); err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeMemberAvailability: insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repo: SetBrigadeMemberAvailability: commit tx: %w", err)
	}

	return &models.SetBrigadeMemberAvailabilityResult{Member: updated}, nil
}

func (m *MemberRepoStruct) ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error) {
	whereParts := []string{"brigade_id = $1"}
	args := []any{in.BrigadeID}

	addWhere := func(condition string, value any) {
		args = append(args, value)
		whereParts = append(whereParts, fmt.Sprintf(condition, len(args)))
	}

	if in.Active != nil {
		addWhere("active = $%d", *in.Active)
	}
	if in.Role != nil {
		addWhere("role = $%d", string(*in.Role))
	}
	if in.AvailabilityStatus != nil {
		addWhere("availability_status = $%d", string(*in.AvailabilityStatus))
	}

	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM brigade_members %s", whereSQL)

	var total int64
	if err := m.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeMembers: count: %w", err)
	}

	args = append(args, in.Limit, in.Offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	query := fmt.Sprintf(`
		SELECT
			id,
			brigade_id,
			user_id,
			profile_id,
			role,
			active,
			availability_status,
			availability_status_changed_at,
			joined_at,
			left_at,
			created_at,
			updated_at
		FROM brigade_members
		%s
		ORDER BY joined_at DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, limitArg, offsetArg)

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeMembers: query: %w", err)
	}
	defer rows.Close()

	members := make([]*models.BrigadeMember, 0)
	for rows.Next() {
		member, err := scanBrigadeMember(rows)
		if err != nil {
			return nil, fmt.Errorf("repo: ListBrigadeMembers: scan: %w", err)
		}
		members = append(members, member)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: ListBrigadeMembers: rows: %w", err)
	}

	return &models.ListBrigadeMembersResult{Members: members, Total: total}, nil
}

func (m *MemberRepoStruct) GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error) {
	whereActive := ""
	if in.OnlyActive {
		whereActive = "AND bm.active = true"
	}

	query := fmt.Sprintf(`
		SELECT
			b.id,
			b.department_id,
			b.name,
			b.description,
			b.status,
			b.specialization,
			b.created_at,
			b.updated_at,
			b.deactivated_at,
			b.archived_at,
			bm.id,
			bm.brigade_id,
			bm.user_id,
			bm.profile_id,
			bm.role,
			bm.active,
			bm.availability_status,
			bm.availability_status_changed_at,
			bm.joined_at,
			bm.left_at,
			bm.created_at,
			bm.updated_at
		FROM brigade_members bm
		JOIN brigades b ON b.id = bm.brigade_id
		WHERE bm.user_id = $1
		%s
		ORDER BY bm.joined_at DESC
		LIMIT 1
	`, whereActive)

	row := m.db.QueryRowContext(ctx, query, in.UserID)
	brigade, member, err := scanBrigadeWithMember(row)
	if err != nil {
		return nil, fmt.Errorf("repo: GetBrigadeByUserID: scan: %w", err)
	}

	return &models.GetBrigadeByUserIDResult{Brigade: brigade, Member: member}, nil
}

func (m *MemberRepoStruct) GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error) {
	whereParts := []string{"brigade_id = $1"}
	args := []any{in.BrigadeID}
	if in.MemberID != nil {
		args = append(args, *in.MemberID)
		whereParts = append(whereParts, fmt.Sprintf("member_id = $%d", len(args)))
	}
	return m.listBrigadeMemberHistory(ctx, whereParts, args, in.Limit, in.Offset)
}

func (m *MemberRepoStruct) GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error) {
	whereParts := []string{"brigade_id = $1"}
	args := []any{in.BrigadeID}
	if in.MemberID != nil {
		args = append(args, *in.MemberID)
		whereParts = append(whereParts, fmt.Sprintf("member_id = $%d", len(args)))
	}
	return m.listBrigadeMemberStatusHistory(ctx, whereParts, args, in.Limit, in.Offset)
}

func (m *MemberRepoStruct) getBrigadeMemberByIDForUpdate(ctx context.Context, tx *sql.Tx, brigadeID uuid.UUID, memberID uuid.UUID) (*models.BrigadeMember, error) {
	const query = `
		SELECT
			id,
			brigade_id,
			user_id,
			profile_id,
			role,
			active,
			availability_status,
			availability_status_changed_at,
			joined_at,
			left_at,
			created_at,
			updated_at
		FROM brigade_members
		WHERE id = $1 AND brigade_id = $2
		FOR UPDATE
	`
	return scanBrigadeMember(tx.QueryRowContext(ctx, query, memberID, brigadeID))
}

func (m *MemberRepoStruct) insertBrigadeMemberHistory(ctx context.Context, tx *sql.Tx, member *models.BrigadeMember, action models.BrigadeMemberHistoryAction, oldRole *models.BrigadeMemberRole, newRole *models.BrigadeMemberRole, changedBy *uuid.UUID, requestID *string) error {
	const query = `
		INSERT INTO brigade_member_history (
			brigade_id,
			member_id,
			user_id,
			profile_id,
			action,
			old_role,
			new_role,
			changed_by_user_id,
			request_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	return execMemberHistoryRoleQuery(ctx, tx, query, member, action, oldRole, newRole, changedBy, requestID)
}

func execMemberHistoryRoleQuery(ctx context.Context, tx *sql.Tx, query string, member *models.BrigadeMember, action models.BrigadeMemberHistoryAction, oldRole *models.BrigadeMemberRole, newRole *models.BrigadeMemberRole, changedBy *uuid.UUID, requestID *string) error {
	var oldRoleValue *string
	if oldRole != nil {
		value := string(*oldRole)
		oldRoleValue = &value
	}
	var newRoleValue *string
	if newRole != nil {
		value := string(*newRole)
		newRoleValue = &value
	}

	_, err := tx.ExecContext(ctx, query, member.BrigadeID, member.ID, member.UserID, member.ProfileID, string(action), oldRoleValue, newRoleValue, changedBy, requestID)
	return err
}

func (m *MemberRepoStruct) insertBrigadeMemberStatusHistory(ctx context.Context, tx *sql.Tx, member *models.BrigadeMember, fromStatus *models.BrigadeMemberAvailabilityStatus, toStatus models.BrigadeMemberAvailabilityStatus, reason string, changedBy *uuid.UUID, requestID *string) error {
	const query = `
		INSERT INTO brigade_member_status_history (
			brigade_id,
			member_id,
			user_id,
			from_status,
			to_status,
			reason,
			changed_by_user_id,
			request_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	var fromStatusValue *string
	if fromStatus != nil {
		value := string(*fromStatus)
		fromStatusValue = &value
	}

	_, err := tx.ExecContext(ctx, query, member.BrigadeID, member.ID, member.UserID, fromStatusValue, string(toStatus), reason, changedBy, requestID)
	return err
}

func scanBrigadeMember(row scanner) (*models.BrigadeMember, error) {
	var member models.BrigadeMember
	var profileID sql.NullString
	var leftAt sql.NullTime

	err := row.Scan(
		&member.ID,
		&member.BrigadeID,
		&member.UserID,
		&profileID,
		&member.Role,
		&member.Active,
		&member.AvailabilityStatus,
		&member.AvailabilityStatusChangedAt,
		&member.JoinedAt,
		&leftAt,
		&member.CreatedAt,
		&member.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, err
	}

	if profileID.Valid {
		id, err := uuid.Parse(profileID.String)
		if err != nil {
			return nil, fmt.Errorf("parse profile_id: %w", err)
		}
		member.ProfileID = &id
	}
	if leftAt.Valid {
		member.LeftAt = &leftAt.Time
	}

	return &member, nil
}

func scanBrigadeWithMember(row scanner) (*models.Brigade, *models.BrigadeMember, error) {
	brigade, member, err := scanBrigadeWithMemberRaw(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, models.ErrNotFound
		}
		return nil, nil, err
	}
	return brigade, member, nil
}

func scanBrigadeWithMemberRaw(row scanner) (*models.Brigade, *models.BrigadeMember, error) {
	var brigade models.Brigade
	var member models.BrigadeMember
	var specialization sql.NullString
	var deactivatedAt sql.NullTime
	var archivedAt sql.NullTime
	var profileID sql.NullString
	var leftAt sql.NullTime

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
		&member.ID,
		&member.BrigadeID,
		&member.UserID,
		&profileID,
		&member.Role,
		&member.Active,
		&member.AvailabilityStatus,
		&member.AvailabilityStatusChangedAt,
		&member.JoinedAt,
		&leftAt,
		&member.CreatedAt,
		&member.UpdatedAt,
	)
	if err != nil {
		return nil, nil, err
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
	if profileID.Valid {
		id, err := uuid.Parse(profileID.String)
		if err != nil {
			return nil, nil, fmt.Errorf("parse profile_id: %w", err)
		}
		member.ProfileID = &id
	}
	if leftAt.Valid {
		member.LeftAt = &leftAt.Time
	}

	return &brigade, &member, nil
}

func (m *MemberRepoStruct) listBrigadeMemberHistory(ctx context.Context, whereParts []string, args []any, limit int32, offset int32) (*models.GetBrigadeMemberHistoryResult, error) {
	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM brigade_member_history %s", whereSQL)
	var total int64
	if err := m.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count: %w", err)
	}

	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT id, brigade_id, member_id, user_id, profile_id, action, old_role, new_role, changed_by_user_id, request_id, created_at
		FROM brigade_member_history
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, len(args)-1, len(args))

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	history := make([]*models.BrigadeMemberHistory, 0)
	for rows.Next() {
		item, err := scanBrigadeMemberHistory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		history = append(history, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}

	return &models.GetBrigadeMemberHistoryResult{History: history, Total: total}, nil
}

func scanBrigadeMemberHistory(row scanner) (*models.BrigadeMemberHistory, error) {
	var item models.BrigadeMemberHistory
	var memberID sql.NullString
	var profileID sql.NullString
	var oldRole sql.NullString
	var newRole sql.NullString
	var changedBy sql.NullString
	var requestID sql.NullString

	err := row.Scan(&item.ID, &item.BrigadeID, &memberID, &item.UserID, &profileID, &item.Action, &oldRole, &newRole, &changedBy, &requestID, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	if memberID.Valid {
		id, err := uuid.Parse(memberID.String)
		if err != nil {
			return nil, fmt.Errorf("parse member_id: %w", err)
		}
		item.MemberID = &id
	}
	if profileID.Valid {
		id, err := uuid.Parse(profileID.String)
		if err != nil {
			return nil, fmt.Errorf("parse profile_id: %w", err)
		}
		item.ProfileID = &id
	}
	if oldRole.Valid {
		value := models.BrigadeMemberRole(oldRole.String)
		item.OldRole = &value
	}
	if newRole.Valid {
		value := models.BrigadeMemberRole(newRole.String)
		item.NewRole = &value
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

func (m *MemberRepoStruct) listBrigadeMemberStatusHistory(ctx context.Context, whereParts []string, args []any, limit int32, offset int32) (*models.GetBrigadeMemberStatusHistoryResult, error) {
	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM brigade_member_status_history %s", whereSQL)
	var total int64
	if err := m.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count: %w", err)
	}

	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT id, brigade_id, member_id, user_id, from_status, to_status, reason, changed_by_user_id, request_id, created_at
		FROM brigade_member_status_history
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, len(args)-1, len(args))

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	history := make([]*models.BrigadeMemberStatusHistory, 0)
	for rows.Next() {
		item, err := scanBrigadeMemberStatusHistory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		history = append(history, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return &models.GetBrigadeMemberStatusHistoryResult{History: history, Total: total}, nil
}

func scanBrigadeMemberStatusHistory(row scanner) (*models.BrigadeMemberStatusHistory, error) {
	var item models.BrigadeMemberStatusHistory
	var memberID sql.NullString
	var fromStatus sql.NullString
	var changedBy sql.NullString
	var requestID sql.NullString

	err := row.Scan(&item.ID, &item.BrigadeID, &memberID, &item.UserID, &fromStatus, &item.ToStatus, &item.Reason, &changedBy, &requestID, &item.CreatedAt)
	if err != nil {
		return nil, err
	}
	if memberID.Valid {
		id, err := uuid.Parse(memberID.String)
		if err != nil {
			return nil, fmt.Errorf("parse member_id: %w", err)
		}
		item.MemberID = &id
	}
	if fromStatus.Valid {
		value := models.BrigadeMemberAvailabilityStatus(fromStatus.String)
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

func isMemberUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}

	if pqErr.Code != "23505" {
		return false
	}

	return pqErr.Constraint == "" ||
		pqErr.Constraint == "brigade_members_active_user_uidx" ||
		pqErr.Constraint == "brigade_members_active_profile_uidx"
}
