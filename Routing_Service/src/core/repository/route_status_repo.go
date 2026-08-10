package repository

import (
	"context"
	"errors"
	"fmt"

	"routing/models"

	"github.com/jackc/pgx/v5"
)

func (r *RouteRepo) UpdateStatus(
	ctx context.Context,
	id string,
	status models.RouteStatus,
) (*models.Route, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: begin route status: %w", err)
	}
	defer tx.Rollback(ctx)

	const query = `UPDATE routes
 SET status = $2, updated_at = now()
 WHERE id = $1
 RETURNING
  id,
  ticket_id,
  brigade_id,
  status,
  origin,
  destination,
  waypoints,
  options,
  calculation,
  revision,
  created_at,
  updated_at`

	route, err := scanRoute(tx.QueryRow(ctx, query, id, status))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: update route status: %w", err)
	}
	if err = appendEvent(
		ctx,
		tx,
		"routing.route.status_changed.v1",
		route,
	); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: commit route status: %w", err)
	}
	return route, nil
}
