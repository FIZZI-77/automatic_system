package repository

import (
	"context"
	"fmt"

	"asset/models"

	"github.com/google/uuid"
)

// ListIncidents возвращает историю объекта от новых событий к старым и количество записей.
func (r *AssetRepoStruct) ListIncidents(ctx context.Context, assetID uuid.UUID, limit, offset int) ([]models.Incident, int, error) {
	var total int
	err := r.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM asset_incidents WHERE asset_id=assets.id)
		FROM assets WHERE id=$1`, assetID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count asset incidents: %w", err)
	}

	rows, err := r.db.Query(ctx, `SELECT id, asset_id, ticket_id, failure_type, description, source, priority, repeated, occurred_at
		FROM asset_incidents WHERE asset_id=$1 ORDER BY occurred_at DESC, id DESC LIMIT $2 OFFSET $3`, assetID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list asset incidents: %w", err)
	}
	defer rows.Close()

	incidents := make([]models.Incident, 0, limit)
	for rows.Next() {
		var incident models.Incident
		if err := rows.Scan(&incident.ID, &incident.AssetID, &incident.TicketID, &incident.FailureType,
			&incident.Description, &incident.Source, &incident.Priority, &incident.Repeated, &incident.OccurredAt); err != nil {
			return nil, 0, fmt.Errorf("scan asset incident: %w", err)
		}
		incidents = append(incidents, incident)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("read asset incidents: %w", err)
	}
	return incidents, total, nil
}
