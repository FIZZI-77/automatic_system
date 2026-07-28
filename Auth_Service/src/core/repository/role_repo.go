package repository

import (
	"context"
	"fmt"
	"github.com/google/uuid"
)

type RoleRepoStruct struct {
	writeDB DBTX
	readDB  DBTX
}

func NewRoleRepoStruct(writeDB DBTX, readDB ...DBTX) *RoleRepoStruct {
	reader := writeDB
	if len(readDB) > 0 && readDB[0] != nil {
		reader = readDB[0]
	}
	return &RoleRepoStruct{writeDB: writeDB, readDB: reader}
}

func (r *RoleRepoStruct) GetRolesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var roles []string

	const query = `SELECT r.name FROM roles r 
    JOIN user_roles u
    ON u.role_id = r.id 
    WHERE u.user_id = $1`

	rows, err := r.readDB.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("role_repo: GetRolesByUserID(): cant exec query: %w", err)
	}
	defer rows.Close()

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
	_, err := r.writeDB.Exec(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("role_repo: AssignRoleToUser(): cant exec query: %w", err)
	}
	return nil
}
