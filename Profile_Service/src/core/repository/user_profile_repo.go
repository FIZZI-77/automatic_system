package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"profile/models"
)

type scanner interface {
	Scan(dest ...any) error
}

type UserProfileRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

var _ UserProfileRepository = (*UserProfileRepoStruct)(nil)

func NewUserProfileRepository(writePool *pgxpool.Pool, readPool *pgxpool.Pool) *UserProfileRepoStruct {
	if readPool == nil {
		readPool = writePool
	}
	return &UserProfileRepoStruct{writePool: writePool, readPool: readPool}
}

func (u *UserProfileRepoStruct) CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error) {
	tx, err := beginCommandTx(ctx, u.writePool)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateUserProfile(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	profile, err := u.createUserProfile(ctx, tx, in)
	if err != nil {
		return nil, err
	}

	if err = insertOutboxEvent(ctx, tx, "user_profile", profile.ID, "UserProfileCreated", in.ActorUserID, profile); err != nil {
		return nil, fmt.Errorf("repository: CreateUserProfile(): insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: CreateUserProfile(): commit: %w", err)
	}

	return &models.CreateUserProfileResult{UserProfile: profile}, nil
}

func (u *UserProfileRepoStruct) createUserProfile(ctx context.Context, q Querier, in *models.CreateUserProfileInput) (*models.UserProfile, error) {
	const query = `
		INSERT INTO user_profiles (
			user_id,
			full_name,
			phone,
			avatar_file_id,
			preferred_contact_method
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING
			id,
			user_id,
			full_name,
			phone,
			avatar_file_id,
			preferred_contact_method,
			created_at,
			updated_at
	`

	profile, err := scanUserProfile(q.QueryRow(
		ctx,
		query,
		in.UserID,
		strings.TrimSpace(in.FullName),
		trimOptionalString(in.Phone),
		in.AvatarFileID,
		in.PreferredContactMethod,
	))
	if err != nil {
		return nil, mapDatabaseError("CreateUserProfile()", err)
	}

	return profile, nil
}

func (u *UserProfileRepoStruct) UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error) {
	tx, err := beginCommandTx(ctx, u.writePool)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateUserProfile(): begin tx: %w", err)
	}
	defer rollbackTxOnCancel(ctx, tx)()

	const query = `
		UPDATE user_profiles
		SET
			full_name = COALESCE($1, full_name),
			phone = CASE WHEN $3 THEN NULL ELSE COALESCE($2, phone) END,
			avatar_file_id = CASE WHEN $5 THEN NULL ELSE COALESCE($4, avatar_file_id) END,
			preferred_contact_method = COALESCE($6, preferred_contact_method),
			updated_at = now()
		WHERE id = $7
		RETURNING
			id,
			user_id,
			full_name,
			phone,
			avatar_file_id,
			preferred_contact_method,
			created_at,
			updated_at
	`

	profile, err := scanUserProfile(tx.QueryRow(
		ctx,
		query,
		trimOptionalString(in.FullName),
		trimOptionalString(in.Phone),
		in.ClearPhone,
		in.AvatarFileID,
		in.ClearAvatarFileID,
		in.PreferredContactMethod,
		in.ID,
	))
	if err != nil {
		return nil, mapDatabaseError("UpdateUserProfile()", err)
	}

	if err = insertOutboxEvent(ctx, tx, "user_profile", profile.ID, "UserProfileUpdated", in.ActorUserID, profile); err != nil {
		return nil, fmt.Errorf("repository: UpdateUserProfile(): insert outbox event: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: UpdateUserProfile(): commit: %w", err)
	}

	return &models.UpdateUserProfileResult{UserProfile: profile}, nil
}

func (u *UserProfileRepoStruct) GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error) {
	const query = `
		SELECT id, user_id, full_name, phone, avatar_file_id,
		       preferred_contact_method, created_at, updated_at
		FROM user_profiles
		WHERE id = $1
	`

	profile, err := scanUserProfile(u.readPool.QueryRow(ctx, query, in.ID))
	if err != nil {
		return nil, mapDatabaseError("GetUserProfileByID()", err)
	}

	return &models.GetUserProfileByIDResult{UserProfile: profile}, nil
}

func (u *UserProfileRepoStruct) GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error) {
	const query = `
		SELECT id, user_id, full_name, phone, avatar_file_id,
		       preferred_contact_method, created_at, updated_at
		FROM user_profiles
		WHERE user_id = $1
	`

	profile, err := scanUserProfile(u.readPool.QueryRow(ctx, query, in.UserID))
	if err != nil {
		return nil, mapDatabaseError("GetUserProfileByUserID()", err)
	}

	return &models.GetUserProfileByUserIDResult{UserProfile: profile}, nil
}

func (u *UserProfileRepoStruct) ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error) {
	whereSQL := ""
	args := make([]any, 0, 3)
	if in.Query != nil {
		args = append(args, "%"+strings.TrimSpace(*in.Query)+"%")
		whereSQL = "WHERE full_name ILIKE $1 OR phone ILIKE $1"
	}

	countQuery := "SELECT COUNT(*) FROM user_profiles " + whereSQL
	var total int64
	if err := u.readPool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, mapDatabaseError("ListUserProfiles(): count", err)
	}

	args = append(args, in.Limit, in.Offset)
	limitArg := len(args) - 1
	offsetArg := len(args)
	query := fmt.Sprintf(`
		SELECT id, user_id, full_name, phone, avatar_file_id,
		       preferred_contact_method, created_at, updated_at
		FROM user_profiles
		%s
		ORDER BY %s %s, id ASC
		LIMIT $%d OFFSET $%d
	`, whereSQL, userProfileSortColumn(in.SortBy), sortOrderSQL(in.SortOrder), limitArg, offsetArg)

	rows, err := u.readPool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapDatabaseError("ListUserProfiles(): query", err)
	}
	defer rows.Close()

	profiles := make([]*models.UserProfile, 0)
	for rows.Next() {
		profile, scanErr := scanUserProfile(rows)
		if scanErr != nil {
			return nil, mapDatabaseError("ListUserProfiles(): scan", scanErr)
		}
		profiles = append(profiles, profile)
	}
	if err = rows.Err(); err != nil {
		return nil, mapDatabaseError("ListUserProfiles(): rows", err)
	}

	return &models.ListUserProfilesResult{UserProfiles: profiles, Total: total}, nil
}

func scanUserProfile(s scanner) (*models.UserProfile, error) {
	profile := &models.UserProfile{}
	err := s.Scan(
		&profile.ID,
		&profile.UserID,
		&profile.FullName,
		&profile.Phone,
		&profile.AvatarFileID,
		&profile.PreferredContactMethod,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

func userProfileSortColumn(sortBy models.UserProfileSortBy) string {
	switch sortBy {
	case models.UserProfileSortByUpdatedAt:
		return "updated_at"
	case models.UserProfileSortByFullName:
		return "full_name"
	default:
		return "created_at"
	}
}

func trimOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	return &trimmed
}
