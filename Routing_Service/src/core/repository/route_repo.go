package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"routing/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RouteRepo struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

func NewRouteRepo(
	writePool *pgxpool.Pool,
	readPool *pgxpool.Pool,
) *RouteRepo {
	if readPool == nil {
		readPool = writePool
	}
	return &RouteRepo{
		writePool: writePool,
		readPool:  readPool,
	}
}

func (r *RouteRepo) CreateRoute(
	ctx context.Context,
	route *models.Route,
) (*models.Route, error) {
	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: begin create route: %w", err)
	}
	defer tx.Rollback(ctx)

	if err = writeRoute(ctx, tx, route); err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) && databaseError.ConstraintName == "routes_one_open_route_per_ticket_idx" {
			_ = tx.Rollback(ctx)
			existing, lookupErr := r.GetOpenRouteByTicket(ctx, route.TicketID)
			if lookupErr != nil {
				return nil, lookupErr
			}
			if existing.BrigadeID != route.BrigadeID {
				return nil, models.ErrConflict
			}
			return existing, nil
		}
		return nil, err
	}
	if err = appendEvent(ctx, tx, "routing.route.created.v1", route); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: commit create route: %w", err)
	}
	return route, nil
}

func (r *RouteRepo) GetRoute(
	ctx context.Context,
	id string,
) (*models.Route, error) {
	const query = `SELECT
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
  updated_at
 FROM routes
 WHERE id = $1`

	route, err := scanRoute(r.readPool.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: get route: %w", err)
	}
	return route, nil
}

func (r *RouteRepo) GetOpenRouteByTicket(ctx context.Context, ticketID string) (*models.Route, error) {
	const query = `SELECT
  id, ticket_id, brigade_id, status, origin, destination, waypoints,
  options, calculation, revision, created_at, updated_at
 FROM routes
 WHERE ticket_id = $1 AND status IN ('PLANNED', 'ACTIVE')
 ORDER BY created_at DESC
 LIMIT 1`

	route, err := scanRoute(r.readPool.QueryRow(ctx, query, ticketID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: get open route by ticket: %w", err)
	}
	return route, nil
}
func (r *RouteRepo) UpdateCalculation(
	ctx context.Context,
	route *models.Route,
) (*models.Route, error) {
	origin, err := json.Marshal(route.Origin)
	if err != nil {
		return nil, fmt.Errorf("repository: encode origin: %w", err)
	}
	calculation, err := json.Marshal(route.Calculation)
	if err != nil {
		return nil, fmt.Errorf("repository: encode calculation: %w", err)
	}

	tx, err := r.writePool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("repository: begin recalculate route: %w", err)
	}
	defer tx.Rollback(ctx)

	const query = `UPDATE routes
 SET
  origin = $2,
  calculation = $3,
  revision = $4,
  updated_at = $5
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

	updated, err := scanRoute(
		tx.QueryRow(
			ctx,
			query,
			route.ID,
			origin,
			calculation,
			route.Revision,
			route.UpdatedAt,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: recalculate route: %w", err)
	}
	if err = appendEvent(ctx, tx, "routing.route.recalculated.v1", updated); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: commit recalculate route: %w", err)
	}
	return updated, nil
}

func (r *RouteRepo) ListRoutes(
	ctx context.Context,
	in *models.ListRoutesInput,
) (*models.ListRoutesResult, error) {
	where := []string{"TRUE"}
	args := make([]any, 0, 5)

	add := func(expression string, value any) {
		args = append(args, value)
		where = append(
			where,
			fmt.Sprintf(expression, len(args)),
		)
	}
	if in.TicketID != nil {
		add("ticket_id = $%d", *in.TicketID)
	}
	if in.BrigadeID != nil {
		add("brigade_id = $%d", *in.BrigadeID)
	}
	if in.Status != nil {
		add("status = $%d", *in.Status)
	}

	clause := strings.Join(where, " AND ")
	var total int64
	if err := r.readPool.QueryRow(
		ctx,
		"SELECT count(*) FROM routes WHERE "+clause,
		args...,
	).Scan(&total); err != nil {
		return nil, fmt.Errorf("repository: count routes: %w", err)
	}

	args = append(args, in.Limit, in.Offset)
	query := `SELECT
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
  updated_at
 FROM routes
 WHERE ` + clause + fmt.Sprintf(
		" ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		len(args)-1,
		len(args),
	)

	rows, err := r.readPool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("repository: list routes: %w", err)
	}
	defer rows.Close()

	result := &models.ListRoutesResult{
		Routes: make([]*models.Route, 0, in.Limit),
		Total:  total,
	}
	for rows.Next() {
		route, scanErr := scanRoute(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("repository: scan route: %w", scanErr)
		}
		result.Routes = append(result.Routes, route)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repository: route rows: %w", err)
	}
	return result, nil
}

func writeRoute(
	ctx context.Context,
	tx pgx.Tx,
	route *models.Route,
) error {
	origin, err := json.Marshal(route.Origin)
	if err != nil {
		return fmt.Errorf("repository: encode origin: %w", err)
	}
	destination, err := json.Marshal(route.Destination)
	if err != nil {
		return fmt.Errorf("repository: encode destination: %w", err)
	}
	waypoints, err := json.Marshal(route.Waypoints)
	if err != nil {
		return fmt.Errorf("repository: encode waypoints: %w", err)
	}
	options, err := json.Marshal(route.Options)
	if err != nil {
		return fmt.Errorf("repository: encode options: %w", err)
	}
	calculation, err := json.Marshal(route.Calculation)
	if err != nil {
		return fmt.Errorf("repository: encode calculation: %w", err)
	}

	const query = `INSERT INTO routes(
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
  updated_at
 ) VALUES(
  $1, $2, $3, $4, $5, $6,
  $7, $8, $9, $10, $11, $12
 )`
	if _, err = tx.Exec(
		ctx,
		query,
		route.ID,
		route.TicketID,
		route.BrigadeID,
		route.Status,
		origin,
		destination,
		waypoints,
		options,
		calculation,
		route.Revision,
		route.CreatedAt,
		route.UpdatedAt,
	); err != nil {
		return fmt.Errorf("repository: create route: %w", err)
	}
	return nil
}

func appendEvent(
	ctx context.Context,
	tx pgx.Tx,
	eventType string,
	route *models.Route,
) error {
	payload, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("repository: encode route event: %w", err)
	}
	const query = `INSERT INTO outbox_events(
  aggregate_id,
  event_type,
  payload
 ) VALUES($1, $2, $3)`
	if _, err = tx.Exec(
		ctx,
		query,
		route.ID,
		eventType,
		payload,
	); err != nil {
		return fmt.Errorf("repository: append route event: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRoute(row rowScanner) (*models.Route, error) {
	route := new(models.Route)
	var origin []byte
	var destination []byte
	var waypoints []byte
	var options []byte
	var calculation []byte

	if err := row.Scan(
		&route.ID,
		&route.TicketID,
		&route.BrigadeID,
		&route.Status,
		&origin,
		&destination,
		&waypoints,
		&options,
		&calculation,
		&route.Revision,
		&route.CreatedAt,
		&route.UpdatedAt,
	); err != nil {
		return nil, err
	}

	values := []struct {
		data   []byte
		target any
	}{
		{data: origin, target: &route.Origin},
		{data: destination, target: &route.Destination},
		{data: waypoints, target: &route.Waypoints},
		{data: options, target: &route.Options},
		{data: calculation, target: &route.Calculation},
	}
	for _, value := range values {
		if err := json.Unmarshal(value.data, value.target); err != nil {
			return nil, fmt.Errorf("decode route: %w", err)
		}
	}
	return route, nil
}
