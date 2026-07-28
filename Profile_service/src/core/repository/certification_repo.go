package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"profile/models"
)

type CertificationRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

var _ CertificationRepository = (*CertificationRepoStruct)(nil)

func NewCertificationRepository(writePool *pgxpool.Pool, readPool *pgxpool.Pool) *CertificationRepoStruct {
	if readPool == nil {
		readPool = writePool
	}
	return &CertificationRepoStruct{writePool: writePool, readPool: readPool}
}

func (r *CertificationRepoStruct) CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateCertificationType(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		INSERT INTO certification_types (code, name, description, default_validity_days, requires_file)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, code, name, description, default_validity_days, requires_file, active, created_at, updated_at
	`
	item, err := scanCertificationType(tx.QueryRow(ctx, query,
		strings.TrimSpace(in.Code),
		strings.TrimSpace(in.Name),
		trimOptionalString(in.Description),
		in.DefaultValidityDays,
		in.RequiresFile,
	))
	if err != nil {
		return nil, mapDatabaseError("CreateCertificationType()", err)
	}
	if err = insertOutboxEvent(ctx, tx, "certification_type", item.ID, "CertificationTypeCreated", in.ActorUserID, item); err != nil {
		return nil, fmt.Errorf("repository: CreateCertificationType(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: CreateCertificationType(): commit: %w", err)
	}
	return &models.CreateCertificationTypeResult{CertificationType: item}, nil
}

func (r *CertificationRepoStruct) UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateCertificationType(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE certification_types
		SET
			code = COALESCE($1, code),
			name = COALESCE($2, name),
			description = CASE WHEN $4 THEN NULL ELSE COALESCE($3, description) END,
			default_validity_days = CASE WHEN $6 THEN NULL ELSE COALESCE($5, default_validity_days) END,
			requires_file = COALESCE($7, requires_file),
			active = COALESCE($8, active),
			updated_at = now()
		WHERE id = $9
		RETURNING id, code, name, description, default_validity_days, requires_file, active, created_at, updated_at
	`
	item, err := scanCertificationType(tx.QueryRow(ctx, query,
		trimOptionalString(in.Code),
		trimOptionalString(in.Name),
		trimOptionalString(in.Description),
		in.ClearDescription,
		in.DefaultValidityDays,
		in.ClearValidityDays,
		in.RequiresFile,
		in.Active,
		in.ID,
	))
	if err != nil {
		return nil, mapDatabaseError("UpdateCertificationType()", err)
	}
	if err = insertOutboxEvent(ctx, tx, "certification_type", item.ID, "CertificationTypeUpdated", in.ActorUserID, item); err != nil {
		return nil, fmt.Errorf("repository: UpdateCertificationType(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: UpdateCertificationType(): commit: %w", err)
	}
	return &models.UpdateCertificationTypeResult{CertificationType: item}, nil
}

func (r *CertificationRepoStruct) GetCertificationTypeByID(ctx context.Context, id uuid.UUID) (*models.CertificationType, error) {
	const query = `
		SELECT id, code, name, description, default_validity_days, requires_file, active, created_at, updated_at
		FROM certification_types
		WHERE id = $1
	`
	item, err := scanCertificationType(r.readPool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, mapDatabaseError("GetCertificationTypeByID()", err)
	}
	return item, nil
}

func (r *CertificationRepoStruct) ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error) {
	whereParts := make([]string, 0, 2)
	args := make([]any, 0, 4)
	if in.Active != nil {
		args = append(args, *in.Active)
		whereParts = append(whereParts, fmt.Sprintf("active = $%d", len(args)))
	}
	if in.Query != nil {
		args = append(args, "%"+strings.TrimSpace(*in.Query)+"%")
		whereParts = append(whereParts, fmt.Sprintf("(code ILIKE $%[1]d OR name ILIKE $%[1]d)", len(args)))
	}
	whereSQL := ""
	if len(whereParts) > 0 {
		whereSQL = "WHERE " + strings.Join(whereParts, " AND ")
	}
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM certification_types %s", whereSQL)
	var total int64
	if err := r.readPool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, mapDatabaseError("ListCertificationTypes(): count", err)
	}
	args = append(args, in.Limit, in.Offset)
	query := fmt.Sprintf(`
		SELECT id, code, name, description, default_validity_days, requires_file, active, created_at, updated_at
		FROM certification_types
		%s
		ORDER BY created_at DESC, id ASC
		LIMIT $%d OFFSET $%d
	`, whereSQL, len(args)-1, len(args))
	rows, err := r.readPool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapDatabaseError("ListCertificationTypes(): query", err)
	}
	defer rows.Close()
	items := make([]*models.CertificationType, 0)
	for rows.Next() {
		item, scanErr := scanCertificationType(rows)
		if scanErr != nil {
			return nil, mapDatabaseError("ListCertificationTypes(): scan", scanErr)
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, mapDatabaseError("ListCertificationTypes(): rows", err)
	}
	return &models.ListCertificationTypesResult{CertificationTypes: items, Total: total}, nil
}

func (r *CertificationRepoStruct) AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: AddCertificationTypeSkill(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const reactivateQuery = `
		UPDATE certification_type_skills
		SET active = true, proficiency_level = $1, updated_at = now()
		WHERE certification_type_id = $2 AND skill_id = $3 AND active = false
		RETURNING id, certification_type_id, skill_id, proficiency_level, active, created_at, updated_at
	`
	item, err := scanCertificationTypeSkill(tx.QueryRow(ctx, reactivateQuery, trimOptionalString(in.ProficiencyLevel), in.CertificationTypeID, in.SkillID))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapDatabaseError("AddCertificationTypeSkill(): reactivate", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		const insertQuery = `
			INSERT INTO certification_type_skills (certification_type_id, skill_id, proficiency_level)
			VALUES ($1, $2, $3)
			RETURNING id, certification_type_id, skill_id, proficiency_level, active, created_at, updated_at
		`
		item, err = scanCertificationTypeSkill(tx.QueryRow(ctx, insertQuery, in.CertificationTypeID, in.SkillID, trimOptionalString(in.ProficiencyLevel)))
		if err != nil {
			return nil, mapDatabaseError("AddCertificationTypeSkill(): insert", err)
		}
	}
	if err = insertOutboxEvent(ctx, tx, "certification_type", in.CertificationTypeID, "CertificationTypeSkillAdded", in.ActorUserID, item); err != nil {
		return nil, fmt.Errorf("repository: AddCertificationTypeSkill(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: AddCertificationTypeSkill(): commit: %w", err)
	}
	return &models.AddCertificationTypeSkillResult{CertificationTypeSkill: item}, nil
}

func (r *CertificationRepoStruct) RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("repository: RemoveCertificationTypeSkill(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE certification_type_skills
		SET active = false, updated_at = now()
		WHERE certification_type_id = $1 AND skill_id = $2 AND active = true
		RETURNING id, certification_type_id, skill_id, proficiency_level, active, created_at, updated_at
	`
	item, err := scanCertificationTypeSkill(tx.QueryRow(ctx, query, in.CertificationTypeID, in.SkillID))
	if err != nil {
		return mapDatabaseError("RemoveCertificationTypeSkill()", err)
	}
	if err = insertOutboxEvent(ctx, tx, "certification_type", in.CertificationTypeID, "CertificationTypeSkillRemoved", in.ActorUserID, item); err != nil {
		return fmt.Errorf("repository: RemoveCertificationTypeSkill(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("repository: RemoveCertificationTypeSkill(): commit: %w", err)
	}
	return nil
}

func (r *CertificationRepoStruct) ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error) {
	query := `
		SELECT id, certification_type_id, skill_id, proficiency_level, active, created_at, updated_at
		FROM certification_type_skills
		WHERE certification_type_id = $1
	`
	args := []any{in.CertificationTypeID}
	if in.ActiveOnly {
		query += " AND active = true"
	}
	query += " ORDER BY created_at ASC, id ASC"
	rows, err := r.readPool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapDatabaseError("ListCertificationTypeSkills(): query", err)
	}
	defer rows.Close()
	items := make([]*models.CertificationTypeSkill, 0)
	for rows.Next() {
		item, scanErr := scanCertificationTypeSkill(rows)
		if scanErr != nil {
			return nil, mapDatabaseError("ListCertificationTypeSkills(): scan", scanErr)
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, mapDatabaseError("ListCertificationTypeSkills(): rows", err)
	}
	return &models.ListCertificationTypeSkillsResult{Skills: items}, nil
}

func (r *CertificationRepoStruct) UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: UploadWorkProfileCertification(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		INSERT INTO work_profile_certifications (
			work_profile_id, certification_type_id, certificate_number, issuer,
			issued_at, expires_at, certificate_file_id, status
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING')
		RETURNING id, work_profile_id, certification_type_id, certificate_number, issuer,
		          issued_at, expires_at, status, certificate_file_id, verified_by_user_id,
		          verified_at, rejection_reason, created_at, updated_at
	`
	item, err := scanWorkProfileCertification(tx.QueryRow(ctx, query,
		in.WorkProfileID,
		in.CertificationTypeID,
		trimOptionalString(in.CertificateNumber),
		trimOptionalString(in.Issuer),
		in.IssuedAt,
		in.ExpiresAt,
		in.CertificateFileID,
	))
	if err != nil {
		return nil, mapDatabaseError("UploadWorkProfileCertification()", err)
	}
	if err = insertOutboxEvent(ctx, tx, "work_profile_certification", item.ID, "CertificationUploaded", in.ActorUserID, item); err != nil {
		return nil, fmt.Errorf("repository: UploadWorkProfileCertification(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: UploadWorkProfileCertification(): commit: %w", err)
	}
	return &models.UploadWorkProfileCertificationResult{Certification: item}, nil
}

func (r *CertificationRepoStruct) VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error) {
	const operation = "VerifyWorkProfileCertification()"

	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: %s: begin tx: %w", operation, err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	current, err := getWorkProfileCertificationByID(ctx, tx, in.ID, true)
	if err != nil {
		return nil, mapDatabaseError(operation+": get certification", err)
	}
	if current.Status == models.CertificationStatusVerified {
		return commitVerifiedCertificationNoop(ctx, tx, current, operation)
	}
	if current.Status != models.CertificationStatusPending {
		return nil, fmt.Errorf("repository: %s: %w", operation, models.ErrInvalidCertificationStatus)
	}
	if err = ensureWorkProfileCanReceiveQualification(ctx, tx, current.WorkProfileID); err != nil {
		return nil, err
	}

	const updateQuery = `
		UPDATE work_profile_certifications
		SET status = 'VERIFIED', verified_by_user_id = $1, verified_at = now(), updated_at = now()
		WHERE id = $2
		RETURNING id, work_profile_id, certification_type_id, certificate_number, issuer,
		          issued_at, expires_at, status, certificate_file_id, verified_by_user_id,
		          verified_at, rejection_reason, created_at, updated_at
	`
	item, err := scanWorkProfileCertification(tx.QueryRow(ctx, updateQuery, in.ActorUserID, in.ID))
	if err != nil {
		return nil, mapDatabaseError(operation+": update", err)
	}

	grants, err := createCertificationSkillGrants(ctx, tx, item)
	if err != nil {
		return nil, mapDatabaseError(operation+": create skill grants", err)
	}
	if err = publishSkillGrantEvents(ctx, tx, operation, in.ActorUserID, grants); err != nil {
		return nil, err
	}
	payload := map[string]any{"certification": item, "skill_grants": grants}
	if err = insertOutboxEvent(ctx, tx, "work_profile_certification", item.ID, "CertificationVerified", in.ActorUserID, payload); err != nil {
		return nil, fmt.Errorf("repository: %s: insert certification event: %w", operation, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: %s: commit: %w", operation, err)
	}
	return &models.VerifyWorkProfileCertificationResult{Certification: item, SkillGrants: grants}, nil
}

func (r *CertificationRepoStruct) RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: RejectWorkProfileCertification(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	current, err := getWorkProfileCertificationByID(ctx, tx, in.ID, true)
	if err != nil {
		return nil, mapDatabaseError("RejectWorkProfileCertification(): get certification", err)
	}
	if current.Status == models.CertificationStatusRejected {
		if err = tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("repository: RejectWorkProfileCertification(): commit no-op: %w", err)
		}
		return &models.RejectWorkProfileCertificationResult{Certification: current}, nil
	}
	if current.Status != models.CertificationStatusPending {
		return nil, fmt.Errorf("repository: RejectWorkProfileCertification(): %w", models.ErrInvalidCertificationStatus)
	}
	const query = `
		UPDATE work_profile_certifications
		SET status = 'REJECTED', rejection_reason = $1, updated_at = now()
		WHERE id = $2
		RETURNING id, work_profile_id, certification_type_id, certificate_number, issuer,
		          issued_at, expires_at, status, certificate_file_id, verified_by_user_id,
		          verified_at, rejection_reason, created_at, updated_at
	`
	item, err := scanWorkProfileCertification(tx.QueryRow(ctx, query, strings.TrimSpace(in.RejectionReason), in.ID))
	if err != nil {
		return nil, mapDatabaseError("RejectWorkProfileCertification(): update", err)
	}
	if err = insertOutboxEvent(ctx, tx, "work_profile_certification", item.ID, "CertificationRejected", in.ActorUserID, item); err != nil {
		return nil, fmt.Errorf("repository: RejectWorkProfileCertification(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: RejectWorkProfileCertification(): commit: %w", err)
	}
	return &models.RejectWorkProfileCertificationResult{Certification: item}, nil
}

func (r *CertificationRepoStruct) RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error) {
	const operation = "RevokeWorkProfileCertification()"

	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: %s: begin tx: %w", operation, err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	item, grants, err := revokeCertification(ctx, tx, in.ID, models.CertificationStatusRevoked)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"certification": item, "revoked_grants": grants, "reason": strings.TrimSpace(in.Reason)}
	if err = insertOutboxEvent(ctx, tx, "work_profile_certification", item.ID, "CertificationRevoked", in.ActorUserID, payload); err != nil {
		return nil, fmt.Errorf("repository: %s: insert certification event: %w", operation, err)
	}
	if err = publishSkillGrantEvents(ctx, tx, operation, in.ActorUserID, grants); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: %s: commit: %w", operation, err)
	}
	return &models.RevokeWorkProfileCertificationResult{Certification: item, RevokedGrants: grants}, nil
}

func (r *CertificationRepoStruct) ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error) {
	const operation = "ExpireWorkProfileCertifications()"

	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: %s: begin tx: %w", operation, err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	ids, err := selectExpiredCertificationIDs(ctx, tx, in.Limit)
	if err != nil {
		return nil, mapDatabaseError(operation+": select expired certifications", err)
	}

	certs := make([]*models.WorkProfileCertification, 0, len(ids))
	grants := make([]*models.WorkProfileSkillGrant, 0)
	for _, id := range ids {
		cert, revokedGrants, err := expireCertification(ctx, tx, id, in.ActorUserID)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		grants = append(grants, revokedGrants...)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: %s: commit: %w", operation, err)
	}
	return &models.ExpireWorkProfileCertificationsResult{ExpiredCertifications: certs, RevokedGrants: grants}, nil
}

func (r *CertificationRepoStruct) ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error) {
	whereParts := []string{"work_profile_id = $1"}
	args := []any{in.WorkProfileID}
	if in.CertificationTypeID != nil {
		args = append(args, *in.CertificationTypeID)
		whereParts = append(whereParts, fmt.Sprintf("certification_type_id = $%d", len(args)))
	}
	if in.Status != nil {
		args = append(args, *in.Status)
		whereParts = append(whereParts, fmt.Sprintf("status = $%d", len(args)))
	}
	whereSQL := "WHERE " + strings.Join(whereParts, " AND ")
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM work_profile_certifications %s", whereSQL)
	var total int64
	if err := r.readPool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, mapDatabaseError("ListWorkProfileCertifications(): count", err)
	}
	args = append(args, in.Limit, in.Offset)
	query := fmt.Sprintf(`
		SELECT id, work_profile_id, certification_type_id, certificate_number, issuer,
		       issued_at, expires_at, status, certificate_file_id, verified_by_user_id,
		       verified_at, rejection_reason, created_at, updated_at
		FROM work_profile_certifications
		%s
		ORDER BY created_at DESC, id ASC
		LIMIT $%d OFFSET $%d
	`, whereSQL, len(args)-1, len(args))
	rows, err := r.readPool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapDatabaseError("ListWorkProfileCertifications(): query", err)
	}
	defer rows.Close()
	items := make([]*models.WorkProfileCertification, 0)
	for rows.Next() {
		item, scanErr := scanWorkProfileCertification(rows)
		if scanErr != nil {
			return nil, mapDatabaseError("ListWorkProfileCertifications(): scan", scanErr)
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, mapDatabaseError("ListWorkProfileCertifications(): rows", err)
	}
	return &models.ListWorkProfileCertificationsResult{Certifications: items, Total: total}, nil
}

func (r *CertificationRepoStruct) GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: GrantManualWorkProfileSkill(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	if err = ensureWorkProfileCanReceiveQualification(ctx, tx, in.WorkProfileID); err != nil {
		return nil, err
	}
	grant, err := insertSkillGrant(ctx, tx, in.WorkProfileID, in.SkillID, models.SkillGrantSourceTypeManual, nil, in.ProficiencyLevel, in.ValidUntil)
	if err != nil {
		return nil, mapDatabaseError("GrantManualWorkProfileSkill(): insert grant", err)
	}
	payload := map[string]any{"skill_grant": grant, "reason": strings.TrimSpace(in.Reason)}
	if err = insertOutboxEvent(ctx, tx, "work_profile_skill_grant", grant.ID, "WorkProfileSkillGrantChanged", in.ActorUserID, payload); err != nil {
		return nil, fmt.Errorf("repository: GrantManualWorkProfileSkill(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: GrantManualWorkProfileSkill(): commit: %w", err)
	}
	return &models.GrantManualWorkProfileSkillResult{SkillGrant: grant}, nil
}

func (r *CertificationRepoStruct) RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: RevokeWorkProfileSkillGrant(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE work_profile_skill_grants
		SET active = false, revoked_at = now()
		WHERE id = $1 AND active = true
		RETURNING id, work_profile_id, skill_id, source_type, source_id, proficiency_level, valid_until, active, created_at, revoked_at
	`
	grant, err := scanWorkProfileSkillGrant(tx.QueryRow(ctx, query, in.ID))
	if err != nil {
		return nil, mapDatabaseError("RevokeWorkProfileSkillGrant()", err)
	}
	payload := map[string]any{"skill_grant": grant, "reason": strings.TrimSpace(in.Reason)}
	if err = insertOutboxEvent(ctx, tx, "work_profile_skill_grant", grant.ID, "WorkProfileSkillGrantChanged", in.ActorUserID, payload); err != nil {
		return nil, fmt.Errorf("repository: RevokeWorkProfileSkillGrant(): insert outbox event: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: RevokeWorkProfileSkillGrant(): commit: %w", err)
	}
	return &models.RevokeWorkProfileSkillGrantResult{SkillGrant: grant}, nil
}

func (r *CertificationRepoStruct) ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error) {
	grants, err := listEffectiveGrants(ctx, r.readPool, []uuid.UUID{in.WorkProfileID})
	if err != nil {
		return nil, mapDatabaseError("ListEffectiveWorkProfileSkills()", err)
	}
	return &models.ListEffectiveWorkProfileSkillsResult{SkillGrants: grants}, nil
}

func (r *CertificationRepoStruct) BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error) {
	grants, err := listEffectiveGrants(ctx, r.readPool, in.WorkProfileIDs)
	if err != nil {
		return nil, mapDatabaseError("BatchListEffectiveWorkProfileSkills()", err)
	}
	result := &models.BatchListEffectiveWorkProfileSkillsResult{SkillGrantsByWorkProfileID: make(map[uuid.UUID][]*models.WorkProfileSkillGrant, len(in.WorkProfileIDs))}
	for _, id := range in.WorkProfileIDs {
		result.SkillGrantsByWorkProfileID[id] = []*models.WorkProfileSkillGrant{}
	}
	for _, grant := range grants {
		result.SkillGrantsByWorkProfileID[grant.WorkProfileID] = append(result.SkillGrantsByWorkProfileID[grant.WorkProfileID], grant)
	}
	return result, nil
}

func (r *CertificationRepoStruct) CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error) {
	grants, err := listEffectiveGrants(ctx, r.readPool, []uuid.UUID{in.WorkProfileID})
	if err != nil {
		return nil, mapDatabaseError("CheckWorkProfileHasSkills()", err)
	}
	have := make(map[uuid.UUID]struct{}, len(grants))
	for _, grant := range grants {
		have[grant.SkillID] = struct{}{}
	}
	missing := make([]uuid.UUID, 0)
	for _, skillID := range in.RequiredSkillIDs {
		if _, ok := have[skillID]; !ok {
			missing = append(missing, skillID)
		}
	}
	return &models.CheckWorkProfileHasSkillsResult{Allowed: len(missing) == 0, MissingSkillIDs: missing}, nil
}

func scanCertificationType(s scanner) (*models.CertificationType, error) {
	item := &models.CertificationType{}
	err := s.Scan(&item.ID, &item.Code, &item.Name, &item.Description, &item.DefaultValidityDays, &item.RequiresFile, &item.Active, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanCertificationTypeSkill(s scanner) (*models.CertificationTypeSkill, error) {
	item := &models.CertificationTypeSkill{}
	err := s.Scan(&item.ID, &item.CertificationTypeID, &item.SkillID, &item.ProficiencyLevel, &item.Active, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanWorkProfileCertification(s scanner) (*models.WorkProfileCertification, error) {
	item := &models.WorkProfileCertification{}
	err := s.Scan(
		&item.ID,
		&item.WorkProfileID,
		&item.CertificationTypeID,
		&item.CertificateNumber,
		&item.Issuer,
		&item.IssuedAt,
		&item.ExpiresAt,
		&item.Status,
		&item.CertificateFileID,
		&item.VerifiedByUserID,
		&item.VerifiedAt,
		&item.RejectionReason,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	return item, err
}

func scanWorkProfileSkillGrant(s scanner) (*models.WorkProfileSkillGrant, error) {
	item := &models.WorkProfileSkillGrant{}
	err := s.Scan(&item.ID, &item.WorkProfileID, &item.SkillID, &item.SourceType, &item.SourceID, &item.ProficiencyLevel, &item.ValidUntil, &item.Active, &item.CreatedAt, &item.RevokedAt)
	return item, err
}

func getWorkProfileCertificationByID(ctx context.Context, q Querier, id uuid.UUID, forUpdate bool) (*models.WorkProfileCertification, error) {
	lockSQL := ""
	if forUpdate {
		lockSQL = "FOR UPDATE"
	}
	query := fmt.Sprintf(`
		SELECT id, work_profile_id, certification_type_id, certificate_number, issuer,
		       issued_at, expires_at, status, certificate_file_id, verified_by_user_id,
		       verified_at, rejection_reason, created_at, updated_at
		FROM work_profile_certifications
		WHERE id = $1
		%s
	`, lockSQL)
	return scanWorkProfileCertification(q.QueryRow(ctx, query, id))
}

func ensureWorkProfileCanReceiveQualification(ctx context.Context, q Querier, workProfileID uuid.UUID) error {
	const query = `SELECT status FROM work_profiles WHERE id = $1`
	var status models.WorkProfileStatus
	if err := q.QueryRow(ctx, query, workProfileID).Scan(&status); err != nil {
		return mapDatabaseError("ensureWorkProfileCanReceiveQualification()", err)
	}
	if status == models.WorkProfileStatusInactive || status == models.WorkProfileStatusSuspended {
		return fmt.Errorf("repository: ensureWorkProfileCanReceiveQualification(): %w", models.ErrWorkProfileInactive)
	}
	return nil
}

func listActiveCertificationTypeSkills(ctx context.Context, q Querier, certificationTypeID uuid.UUID) ([]*models.CertificationTypeSkill, error) {
	const query = `
		SELECT id, certification_type_id, skill_id, proficiency_level, active, created_at, updated_at
		FROM certification_type_skills
		WHERE certification_type_id = $1 AND active = true
		ORDER BY created_at ASC, id ASC
	`
	rows, err := q.Query(ctx, query, certificationTypeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]*models.CertificationTypeSkill, 0)
	for rows.Next() {
		item, scanErr := scanCertificationTypeSkill(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func insertSkillGrant(ctx context.Context, q Querier, workProfileID uuid.UUID, skillID uuid.UUID, sourceType models.SkillGrantSourceType, sourceID *uuid.UUID, level *string, validUntil *time.Time) (*models.WorkProfileSkillGrant, error) {
	const query = `
		INSERT INTO work_profile_skill_grants (
			work_profile_id, skill_id, source_type, source_id, proficiency_level, valid_until
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, work_profile_id, skill_id, source_type, source_id, proficiency_level, valid_until, active, created_at, revoked_at
	`
	return scanWorkProfileSkillGrant(q.QueryRow(ctx, query, workProfileID, skillID, sourceType, sourceID, trimOptionalString(level), validUntil))
}

func commitVerifiedCertificationNoop(ctx context.Context, tx pgx.Tx, certification *models.WorkProfileCertification, operation string) (*models.VerifyWorkProfileCertificationResult, error) {
	grants, err := listCertificationGrants(ctx, tx, certification.ID)
	if err != nil {
		return nil, mapDatabaseError(operation+": list grants", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: %s: commit no-op: %w", operation, err)
	}
	return &models.VerifyWorkProfileCertificationResult{Certification: certification, SkillGrants: grants}, nil
}

func createCertificationSkillGrants(ctx context.Context, q Querier, certification *models.WorkProfileCertification) ([]*models.WorkProfileSkillGrant, error) {
	typeSkills, err := listActiveCertificationTypeSkills(ctx, q, certification.CertificationTypeID)
	if err != nil {
		return nil, err
	}

	grants := make([]*models.WorkProfileSkillGrant, 0, len(typeSkills))
	for _, typeSkill := range typeSkills {
		grant, err := insertSkillGrant(
			ctx,
			q,
			certification.WorkProfileID,
			typeSkill.SkillID,
			models.SkillGrantSourceTypeCertification,
			&certification.ID,
			typeSkill.ProficiencyLevel,
			certification.ExpiresAt,
		)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, nil
}

func publishSkillGrantEvents(ctx context.Context, q Querier, operation string, actorUserID *uuid.UUID, grants []*models.WorkProfileSkillGrant) error {
	for _, grant := range grants {
		if err := insertOutboxEvent(ctx, q, "work_profile_skill_grant", grant.ID, "WorkProfileSkillGrantChanged", actorUserID, grant); err != nil {
			return fmt.Errorf("repository: %s: insert skill event: %w", operation, err)
		}
	}
	return nil
}

func selectExpiredCertificationIDs(ctx context.Context, q Querier, limit int32) ([]uuid.UUID, error) {
	const query = `
		SELECT id
		FROM work_profile_certifications
		WHERE status = 'VERIFIED' AND expires_at IS NOT NULL AND expires_at <= now()
		ORDER BY expires_at ASC, id ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`
	rows, err := q.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func expireCertification(ctx context.Context, q Querier, certificationID uuid.UUID, actorUserID *uuid.UUID) (*models.WorkProfileCertification, []*models.WorkProfileSkillGrant, error) {
	const operation = "ExpireWorkProfileCertifications()"

	certification, grants, err := revokeCertification(ctx, q, certificationID, models.CertificationStatusExpired)
	if err != nil {
		return nil, nil, fmt.Errorf("repository: %s: expire certification: %w", operation, err)
	}
	if err = insertOutboxEvent(ctx, q, "work_profile_certification", certification.ID, "CertificationExpired", actorUserID, certification); err != nil {
		return nil, nil, fmt.Errorf("repository: %s: insert certification event: %w", operation, err)
	}
	if err = publishSkillGrantEvents(ctx, q, operation, actorUserID, grants); err != nil {
		return nil, nil, fmt.Errorf("repository: %s: publish skill grants: %w", operation, err)
	}
	return certification, grants, nil
}

func listCertificationGrants(ctx context.Context, q Querier, certificationID uuid.UUID) ([]*models.WorkProfileSkillGrant, error) {
	const query = `
		SELECT id, work_profile_id, skill_id, source_type, source_id, proficiency_level, valid_until, active, created_at, revoked_at
		FROM work_profile_skill_grants
		WHERE source_type = 'CERTIFICATION' AND source_id = $1
		ORDER BY created_at ASC, id ASC
	`
	rows, err := q.Query(ctx, query, certificationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]*models.WorkProfileSkillGrant, 0)
	for rows.Next() {
		item, scanErr := scanWorkProfileSkillGrant(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func revokeCertification(ctx context.Context, q Querier, certificationID uuid.UUID, status models.CertificationStatus) (*models.WorkProfileCertification, []*models.WorkProfileSkillGrant, error) {
	current, err := getWorkProfileCertificationByID(ctx, q, certificationID, true)
	if err != nil {
		return nil, nil, mapDatabaseError("revokeCertification(): get certification", err)
	}
	if current.Status == status {
		grants, listErr := listCertificationGrants(ctx, q, certificationID)
		if listErr != nil {
			return nil, nil, mapDatabaseError("revokeCertification(): list grants", listErr)
		}
		return current, grants, nil
	}
	if current.Status != models.CertificationStatusVerified && current.Status != models.CertificationStatusPending {
		return nil, nil, fmt.Errorf("repository: revokeCertification(): %w", models.ErrInvalidCertificationStatus)
	}

	const updateQuery = `
		UPDATE work_profile_certifications
		SET status = $1, updated_at = now()
		WHERE id = $2
		RETURNING id, work_profile_id, certification_type_id, certificate_number, issuer,
		          issued_at, expires_at, status, certificate_file_id, verified_by_user_id,
		          verified_at, rejection_reason, created_at, updated_at
	`
	item, err := scanWorkProfileCertification(q.QueryRow(ctx, updateQuery, status, certificationID))
	if err != nil {
		return nil, nil, mapDatabaseError("revokeCertification(): update certification", err)
	}

	const revokeGrantsQuery = `
		UPDATE work_profile_skill_grants
		SET active = false, revoked_at = now()
		WHERE source_type = 'CERTIFICATION' AND source_id = $1 AND active = true
		RETURNING id, work_profile_id, skill_id, source_type, source_id, proficiency_level, valid_until, active, created_at, revoked_at
	`
	rows, err := q.Query(ctx, revokeGrantsQuery, certificationID)
	if err != nil {
		return nil, nil, mapDatabaseError("revokeCertification(): revoke grants", err)
	}
	defer rows.Close()
	grants := make([]*models.WorkProfileSkillGrant, 0)
	for rows.Next() {
		grant, scanErr := scanWorkProfileSkillGrant(rows)
		if scanErr != nil {
			return nil, nil, mapDatabaseError("revokeCertification(): scan grant", scanErr)
		}
		grants = append(grants, grant)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, mapDatabaseError("revokeCertification(): grant rows", err)
	}
	return item, grants, nil
}

func listEffectiveGrants(ctx context.Context, q Querier, workProfileIDs []uuid.UUID) ([]*models.WorkProfileSkillGrant, error) {
	const query = `
		SELECT wpsg.id, wpsg.work_profile_id, wpsg.skill_id, wpsg.source_type, wpsg.source_id,
		       wpsg.proficiency_level, wpsg.valid_until, wpsg.active, wpsg.created_at, wpsg.revoked_at
		FROM work_profile_skill_grants wpsg
		JOIN work_profiles wp ON wp.id = wpsg.work_profile_id
		LEFT JOIN work_profile_certifications wpc
			ON wpc.id = wpsg.source_id AND wpsg.source_type = 'CERTIFICATION'
		WHERE wpsg.work_profile_id = ANY($1)
		  AND wpsg.active = true
		  AND (wpsg.valid_until IS NULL OR wpsg.valid_until > now())
		  AND wp.status IN ('ACTIVE', 'ON_SHIFT')
		  AND (
		      wpsg.source_type = 'MANUAL'
		      OR (wpc.status = 'VERIFIED' AND (wpc.expires_at IS NULL OR wpc.expires_at > now()))
		  )
		ORDER BY wpsg.work_profile_id ASC, wpsg.skill_id ASC, wpsg.created_at ASC
	`
	rows, err := q.Query(ctx, query, workProfileIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]*models.WorkProfileSkillGrant, 0)
	for rows.Next() {
		item, scanErr := scanWorkProfileSkillGrant(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
