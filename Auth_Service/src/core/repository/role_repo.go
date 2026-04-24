package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
)

type RoleRepoStruct struct {
	db *sql.DB
}

func NewRoleRepoStruct(db *sql.DB) *RoleRepoStruct {
	return &RoleRepoStruct{db: db}
}

func (r *RoleRepoStruct) GetRolesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var roles []string

	const query = `SELECT r.name FROM roles r 
    JOIN user_roles u
    ON u.role_id = r.id 
    WHERE u.user_id = $1`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("role_repo: GetRolesByUserID(): cant exec query: %w", err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			fmt.Printf("role_repo: GetRolesByUserID(): rows.Close(): %v\n", err)
		}
	}(rows)

	for rows.Next() {
		var role string
		err = rows.Scan(&role)
		if err != nil {
			return nil, fmt.Errorf("role_repo: GetRolesByUserID(): rows.Scan(): %w", err)
		}
		roles = append(roles, role)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("role_repo: GetRolesByUserID(): rows.Err(): %w", err)
	}
	return roles, nil
}
func (r *RoleRepoStruct) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error {
	const query = `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING`
	_, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("role_repo: AssignRoleToUser(): cant exec query: %w", err)
	}
	return nil
}
