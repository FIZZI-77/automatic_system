package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ticket/models"
)

const ticketWithRelationColumns = `
	id,
	department_id,
	category_id,
	user_id,
	brigade_id,
	title,
	description,
	status,
	priority,
	address,
	latitude,
	longitude,
	created_at,
	updated_at,
	assigned_at,
	completed_at,
	canceled_at,
	asset_id,
	ticket_type,
	incident_id,
	external_system_id,
	external_id
`

func (t *TicketRepoStruct) CreateRequest(
	ctx context.Context,
	in *models.CreateRequestInput,
) (*models.CreateRequestResult, error) {
	tx, err := beginCommandTx(ctx, t.writePool)

	if err != nil {
		return nil, fmt.Errorf("repository: CreateRequest(): begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	if err = t.lockDuplicateScope(ctx, tx, in.DepartmentID, in.CategoryID); err != nil {
		return nil, fmt.Errorf("repository: CreateRequest(): lock duplicate scope: %w", err)
	}

	if in.ExternalSystemID != nil && in.ExternalID != nil {
		result, found, findErr := t.findExternalRequest(
			ctx,
			tx,
			in.DepartmentID,
			*in.ExternalSystemID,
			*in.ExternalID,
		)

		if findErr != nil {
			return nil, fmt.Errorf("repository: CreateRequest(): find external request: %w", findErr)
		}

		if found {
			return result, nil
		}

	}

	categoryActive, err := t.isCategoryActive(ctx, tx, in.CategoryID)

	if err != nil {
		return nil, fmt.Errorf("repository: CreateRequest(): check category: %w", err)
	}

	if !categoryActive {
		return nil, fmt.Errorf("repository: CreateRequest(): %w", models.ErrCategoryInactive)
	}

	incident, err := t.findDuplicateIncident(ctx, tx, in)

	if err != nil {
		return nil, fmt.Errorf("repository: CreateRequest(): find incident: %w", err)
	}

	duplicateMatched := incident != nil

	if incident == nil {
		incident, err = t.insertRequestTicket(ctx, tx, requestTicketInsert{
			ID:           uuid.New(),
			DepartmentID: in.DepartmentID,
			CategoryID:   in.CategoryID,
			UserID:       in.UserID,
			Type:         models.TicketTypeIncident,
			Title:        in.Title,
			Description:  in.Description,
			Priority:     in.Priority,
			Address:      in.Address,
			Latitude:     in.Latitude,
			Longitude:    in.Longitude,
			AssetID:      in.AssetID,
		})

		if err != nil {
			return nil, fmt.Errorf("repository: CreateRequest(): create incident: %w", err)
		}

		if err = t.recordCreatedTicket(ctx, tx, incident, "Incident created from request"); err != nil {
			return nil, fmt.Errorf("repository: CreateRequest(): record incident: %w", err)
		}

	}

	request, err := t.insertRequestTicket(ctx, tx, requestTicketInsert{
		ID:               uuid.New(),
		DepartmentID:     in.DepartmentID,
		CategoryID:       in.CategoryID,
		UserID:           in.UserID,
		Type:             models.TicketTypeRequest,
		IncidentID:       &incident.ID,
		Title:            in.Title,
		Description:      in.Description,
		Priority:         in.Priority,
		Address:          in.Address,
		Latitude:         in.Latitude,
		Longitude:        in.Longitude,
		AssetID:          in.AssetID,
		ExternalSystemID: in.ExternalSystemID,
		ExternalID:       in.ExternalID,
	})

	if err != nil {
		return nil, fmt.Errorf("repository: CreateRequest(): create request: %w", err)
	}

	if err = t.recordCreatedTicket(ctx, tx, request, "Request created and attached to incident"); err != nil {
		return nil, fmt.Errorf("repository: CreateRequest(): record request: %w", err)
	}

	result := &models.CreateRequestResult{
		Request:          request,
		Incident:         incident,
		DuplicateMatched: duplicateMatched,
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: CreateRequest(): commit: %w", err)
	}

	return result, nil
}

func (t *TicketRepoStruct) AttachRequest(ctx context.Context, in *models.AttachRequestInput) (*models.Ticket, error) {
	return t.changeRequestIncident(ctx, in.RequestID, &in.IncidentID, in.ChangedBy, in.Reason, "ticket.request_attached")
}

func (t *TicketRepoStruct) DetachRequest(ctx context.Context, in *models.DetachRequestInput) (*models.Ticket, error) {
	return t.changeRequestIncident(ctx, in.RequestID, nil, in.ChangedBy, in.Reason, "ticket.request_detached")
}

func (t *TicketRepoStruct) ListIncidentRequests(
	ctx context.Context,
	in *models.ListIncidentRequestsInput,
) ([]*models.Ticket, int64, error) {
	const query = `
		SELECT
			` + ticketWithRelationColumns + `,
			COUNT(*) OVER()
		FROM tickets
		WHERE incident_id = $1
		  AND ticket_type = 'REQUEST'
		  AND status <> 'ARCHIVED'
		ORDER BY created_at DESC, id DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := t.readPool.Query(ctx, query, in.IncidentID, in.Limit, in.Offset)

	if err != nil {
		return nil, 0, fmt.Errorf("repository: ListIncidentRequests(): query: %w", err)
	}

	defer rows.Close()

	requests := make([]*models.Ticket, 0, in.Limit)
	var total int64

	for rows.Next() {
		request, count, scanErr := scanTicketWithRelationAndCount(rows)

		if scanErr != nil {
			return nil, 0, fmt.Errorf("repository: ListIncidentRequests(): scan: %w", scanErr)
		}

		total = count
		requests = append(requests, request)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository: ListIncidentRequests(): rows: %w", err)
	}

	return requests, total, nil
}

func (t *TicketRepoStruct) IncidentHasDepartment(
	ctx context.Context,
	incidentID uuid.UUID,
	departmentID *uuid.UUID,
) (bool, error) {
	if departmentID == nil {
		return false, nil
	}

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM tickets
			WHERE incident_id = $1
			  AND department_id = $2
			  AND ticket_type = 'REQUEST'
			  AND status <> 'ARCHIVED'
		)
	`

	var exists bool

	if err := t.readPool.QueryRow(ctx, query, incidentID, *departmentID).Scan(&exists); err != nil {
		return false, fmt.Errorf("repository: IncidentHasDepartment(): query: %w", err)
	}

	return exists, nil
}

func (t *TicketRepoStruct) lockDuplicateScope(
	ctx context.Context,
	exec Querier,
	departmentID uuid.UUID,
	categoryID uuid.UUID,
) error {
	key := departmentID.String() + ":" + categoryID.String()
	_, err := exec.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)

	return err
}

func (t *TicketRepoStruct) findDuplicateIncident(
	ctx context.Context,
	exec Querier,
	in *models.CreateRequestInput,
) (*models.Ticket, error) {
	const query = `
		SELECT
			` + ticketWithRelationColumns + `
		FROM tickets
		WHERE department_id = $1
		  AND category_id = $2
		  AND ticket_type = 'INCIDENT'
		  AND status IN ('NEW', 'ASSIGNED', 'IN_PROGRESS')
		  AND created_at >= $3
		  AND 2 * 6371000 * asin(
			LEAST(1, sqrt(
				power(sin(radians(latitude - $4) / 2), 2)
				+ cos(radians($4)) * cos(radians(latitude))
				* power(sin(radians(longitude - $5) / 2), 2)
			))
		  ) <= $6
		ORDER BY
		  2 * 6371000 * asin(
			LEAST(1, sqrt(
				power(sin(radians(latitude - $4) / 2), 2)
				+ cos(radians($4)) * cos(radians(latitude))
				* power(sin(radians(longitude - $5) / 2), 2)
			))
		  ),
		  created_at DESC
	LIMIT 1
	FOR UPDATE
	`

	row := exec.QueryRow(
		ctx,
		query,
		in.DepartmentID,
		in.CategoryID,
		time.Now().UTC().Add(-models.DuplicateWindow),
		in.Latitude,
		in.Longitude,
		models.DuplicateRadiusMeters,
	)

	incident, err := scanTicketWithRelation(row)

	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}

	return incident, err
}

func (t *TicketRepoStruct) findExternalRequest(
	ctx context.Context,
	exec Querier,
	departmentID uuid.UUID,
	externalSystemID uuid.UUID,
	externalID string,
) (*models.CreateRequestResult, bool, error) {
	const query = `
		SELECT
			` + ticketWithRelationColumns + `
		FROM tickets
		WHERE department_id = $1
		  AND external_system_id = $2
		  AND external_id = $3
		  AND ticket_type = 'REQUEST'
		FOR UPDATE
	`

	request, err := scanTicketWithRelation(exec.QueryRow(ctx, query, departmentID, externalSystemID, externalID))

	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, err
	}

	if request.IncidentID == nil {
		return nil, false, models.ErrInvalidTicketRelation
	}

	incident, err := t.getTicketWithRelation(ctx, exec, *request.IncidentID, false)

	if err != nil {
		return nil, false, err
	}

	return &models.CreateRequestResult{
		Request:          request,
		Incident:         incident,
		DuplicateMatched: true,
	}, true, nil
}

type requestTicketInsert struct {
	ID           uuid.UUID
	DepartmentID uuid.UUID
	CategoryID   uuid.UUID
	UserID       uuid.UUID
	Type         models.TicketType
	IncidentID   *uuid.UUID

	Title       string
	Description string
	Priority    models.TicketPriority
	Address     string
	Latitude    float64
	Longitude   float64
	AssetID     *uuid.UUID

	ExternalSystemID *uuid.UUID
	ExternalID       *string
}

func (t *TicketRepoStruct) insertRequestTicket(
	ctx context.Context,
	exec Querier,
	in requestTicketInsert,
) (*models.Ticket, error) {
	const query = `
		INSERT INTO tickets (
			id, department_id, category_id, user_id, brigade_id,
			title, description, status, priority,
			address, latitude, longitude,
			created_at, updated_at, assigned_at, completed_at, canceled_at,
			asset_id, ticket_type, incident_id, external_system_id, external_id
		)
		VALUES (
			$1, $2, $3, $4, NULL,
			$5, $6, 'NEW', $7,
			$8, $9, $10,
			now(), now(), NULL, NULL, NULL,
			$11, $12, $13, $14, $15
		)
		RETURNING
			` + ticketWithRelationColumns + `
	`

	row := exec.QueryRow(
		ctx,
		query,
		in.ID,
		in.DepartmentID,
		in.CategoryID,
		in.UserID,
		in.Title,
		in.Description,
		in.Priority,
		in.Address,
		in.Latitude,
		in.Longitude,
		in.AssetID,
		in.Type,
		in.IncidentID,
		in.ExternalSystemID,
		in.ExternalID,
	)

	return scanTicketWithRelation(row)
}

func (t *TicketRepoStruct) recordCreatedTicket(
	ctx context.Context,
	exec Querier,
	ticket *models.Ticket,
	comment string,
) error {
	if err := t.insertTicketStatusHistory(
		ctx,
		exec,
		ticket.ID,
		ticket.DepartmentID,
		nil,
		models.TicketStatusNew,
		&ticket.UserID,
		&comment,
	); err != nil {
		return err
	}

	return t.insertTicketCreatedOutboxEvent(ctx, exec, ticket)
}

func (t *TicketRepoStruct) changeRequestIncident(
	ctx context.Context,
	requestID uuid.UUID,
	incidentID *uuid.UUID,
	changedBy uuid.UUID,
	reason string,
	eventType string,
) (*models.Ticket, error) {
	tx, err := beginCommandTx(ctx, t.writePool)

	if err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): begin tx: %w", err)
	}

	defer rollbackTxOnCancel(ctx, tx)()

	if err = lockRequestRelation(ctx, tx, requestID); err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): lock request relation: %w", err)
	}

	request, err := t.getTicketWithRelation(ctx, tx, requestID, false)

	if err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): get request: %w", err)
	}

	incidentIDs := make([]uuid.UUID, 0, 2)

	if request.IncidentID != nil {
		incidentIDs = append(incidentIDs, *request.IncidentID)
	}

	if incidentID != nil {
		incidentIDs = append(incidentIDs, *incidentID)
	}

	if err = lockIncidentAggregations(ctx, tx, incidentIDs...); err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): lock incidents: %w", err)
	}

	request, err = t.getTicketWithRelationByDepartment(
		ctx,
		tx,
		request.DepartmentID,
		requestID,
		true,
	)

	if err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): lock request: %w", err)
	}

	if request.Type != models.TicketTypeRequest {
		return nil, models.ErrInvalidTicketType
	}

	if incidentID != nil {
		incident, getErr := t.getTicketWithRelation(ctx, tx, *incidentID, false)

		if getErr != nil {
			return nil, fmt.Errorf("repository: changeRequestIncident(): find incident: %w", getErr)
		}

		incident, getErr = t.getTicketWithRelationByDepartment(
			ctx,
			tx,
			incident.DepartmentID,
			*incidentID,
			true,
		)

		if getErr != nil {
			return nil, fmt.Errorf("repository: changeRequestIncident(): get incident: %w", getErr)
		}

		if incident.Type != models.TicketTypeIncident {
			return nil, models.ErrInvalidTicketRelation
		}

		if incident.Status == models.TicketStatusDone || incident.Status == models.TicketStatusCanceled {
			return nil, models.ErrTicketTerminalState
		}

		if request.IncidentID != nil && *request.IncidentID == *incidentID {
			return nil, models.ErrRequestAlreadyAttached
		}

	}

	const query = `
		UPDATE tickets
		SET incident_id = $1,
			updated_at = now()
		WHERE department_id = $2
		  AND id = $3
		  AND ticket_type = 'REQUEST'
		RETURNING
			` + ticketWithRelationColumns + `
	`

	updated, err := scanTicketWithRelation(tx.QueryRow(ctx, query, incidentID, request.DepartmentID, request.ID))

	if err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): update request: %w", err)
	}

	payload := map[string]any{
		"ticket_id":   updated.ID,
		"incident_id": updated.IncidentID,
		"changed_by":  changedBy,
		"reason":      reason,
	}

	if err = t.insertOutboxEvent(ctx, tx, "ticket", updated.ID, eventType, payload); err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): insert event: %w", err)
	}

	if request.IncidentID != nil {

		if err = t.reconcileIncidentCompletion(ctx, tx, *request.IncidentID, changedBy); err != nil {
			return nil, fmt.Errorf("repository: changeRequestIncident(): reconcile previous incident: %w", err)
		}

	}

	if incidentID != nil && (request.IncidentID == nil || *request.IncidentID != *incidentID) {

		if err = t.reconcileIncidentCompletion(ctx, tx, *incidentID, changedBy); err != nil {
			return nil, fmt.Errorf("repository: changeRequestIncident(): reconcile incident: %w", err)
		}

	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("repository: changeRequestIncident(): commit: %w", err)
	}

	return updated, nil
}

func lockRequestRelation(ctx context.Context, exec Querier, requestID uuid.UUID) error {
	key := "request-relation:" + requestID.String()
	_, err := exec.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)

	return err
}

func lockIncidentAggregations(ctx context.Context, exec Querier, incidentIDs ...uuid.UUID) error {
	uniqueIDs := make(map[string]struct{}, len(incidentIDs))
	keys := make([]string, 0, len(incidentIDs))

	for _, incidentID := range incidentIDs {

		if incidentID == uuid.Nil {
			continue
		}

		key := incidentID.String()

		if _, exists := uniqueIDs[key]; exists {
			continue
		}

		uniqueIDs[key] = struct{}{}
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {

		if _, err := exec.Exec(
			ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"incident-aggregation:"+key,
		); err != nil {
			return err
		}

	}

	return nil
}

func (t *TicketRepoStruct) reconcileIncidentCompletion(
	ctx context.Context,
	exec Querier,
	incidentID uuid.UUID,
	changedBy uuid.UUID,
) error {
	incident, err := t.getTicketWithRelation(ctx, exec, incidentID, false)

	if err != nil {
		return err
	}

	if incident.Type != models.TicketTypeIncident {
		return models.ErrInvalidTicketRelation
	}

	if incident.Status == models.TicketStatusDone || incident.Status == models.TicketStatusCanceled {
		return nil
	}

	incident, err = t.getTicketWithRelationByDepartment(
		ctx,
		exec,
		incident.DepartmentID,
		incident.ID,
		true,
	)

	if err != nil {
		return err
	}

	total, incomplete, err := t.incidentPartCounts(ctx, exec, incidentID)

	if err != nil {
		return err
	}

	if total == 0 || incomplete > 0 {
		return nil
	}

	const query = `
		UPDATE tickets
		SET status = 'DONE',
			completed_at = now(),
			updated_at = now()
		WHERE department_id = $1
		  AND id = $2
		  AND ticket_type = 'INCIDENT'
		  AND status NOT IN ('DONE', 'CANCELED')
		RETURNING
			` + ticketWithRelationColumns + `
	`

	completed, err := scanTicketWithRelation(exec.QueryRow(
		ctx,
		query,
		incident.DepartmentID,
		incident.ID,
	))

	if err != nil {
		return err
	}

	comment := "All incident requests completed"

	if err = t.insertTicketStatusHistory(
		ctx,
		exec,
		completed.ID,
		completed.DepartmentID,
		&incident.Status,
		models.TicketStatusDone,
		&changedBy,
		&comment,
	); err != nil {
		return err
	}

	return t.insertOutboxEvent(ctx, exec, "ticket", completed.ID, "ticket.completed", completed)
}

func (t *TicketRepoStruct) incidentPartCounts(
	ctx context.Context,
	exec Querier,
	incidentID uuid.UUID,
) (int64, int64, error) {
	const query = `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status <> 'DONE')
		FROM tickets
		WHERE incident_id = $1
		  AND ticket_type = 'REQUEST'
		  AND status <> 'ARCHIVED'
	`

	var total int64
	var incomplete int64

	if err := exec.QueryRow(ctx, query, incidentID).Scan(&total, &incomplete); err != nil {
		return 0, 0, err
	}

	return total, incomplete, nil
}

func (t *TicketRepoStruct) ensureIncidentPartsComplete(
	ctx context.Context,
	exec Querier,
	incidentID uuid.UUID,
) error {
	total, incomplete, err := t.incidentPartCounts(ctx, exec, incidentID)

	if err != nil {
		return err
	}

	if total > 0 && incomplete > 0 {
		return models.ErrIncidentPartsIncomplete
	}

	return nil
}

func (t *TicketRepoStruct) getTicketWithRelation(
	ctx context.Context,
	exec Querier,
	ticketID uuid.UUID,
	forUpdate bool,
) (*models.Ticket, error) {
	query := `
		SELECT
			` + ticketWithRelationColumns + `
		FROM tickets
		WHERE id = $1
		  AND status <> 'ARCHIVED'
	`

	if forUpdate {
		query += " FOR UPDATE"
	}

	return scanTicketWithRelation(exec.QueryRow(ctx, query, ticketID))
}

func (t *TicketRepoStruct) getTicketWithRelationByDepartment(
	ctx context.Context,
	exec Querier,
	departmentID uuid.UUID,
	ticketID uuid.UUID,
	forUpdate bool,
) (*models.Ticket, error) {
	query := `
		SELECT
			` + ticketWithRelationColumns + `
		FROM tickets
		WHERE department_id = $1
		  AND id = $2
		  AND status <> 'ARCHIVED'
	`

	if forUpdate {
		query += " FOR UPDATE"
	}

	return scanTicketWithRelation(exec.QueryRow(ctx, query, departmentID, ticketID))
}

func scanTicketWithRelation(s scanner) (*models.Ticket, error) {
	ticket, _, err := scanTicketWithRelationValues(s, false)

	return ticket, err
}

func scanTicketWithRelationAndCount(s scanner) (*models.Ticket, int64, error) {
	return scanTicketWithRelationValues(s, true)
}

func scanTicketWithRelationValues(s scanner, withCount bool) (*models.Ticket, int64, error) {
	var ticket models.Ticket

	var brigadeID sql.NullString
	var assignedAt sql.NullTime
	var completedAt sql.NullTime
	var canceledAt sql.NullTime
	var assetID sql.NullString
	var incidentID sql.NullString
	var externalSystemID sql.NullString
	var externalID sql.NullString
	var total int64

	destinations := []any{
		&ticket.ID,
		&ticket.DepartmentID,
		&ticket.CategoryID,
		&ticket.UserID,
		&brigadeID,
		&ticket.Title,
		&ticket.Description,
		&ticket.Status,
		&ticket.Priority,
		&ticket.Address,
		&ticket.Latitude,
		&ticket.Longitude,
		&ticket.CreatedAt,
		&ticket.UpdatedAt,
		&assignedAt,
		&completedAt,
		&canceledAt,
		&assetID,
		&ticket.Type,
		&incidentID,
		&externalSystemID,
		&externalID,
	}

	if withCount {
		destinations = append(destinations, &total)
	}

	if err := s.Scan(destinations...); err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}

		return nil, 0, err
	}

	if err := applyOptionalTicketValues(
		&ticket,
		brigadeID,
		assetID,
		incidentID,
		externalSystemID,
		externalID,
		assignedAt,
		completedAt,
		canceledAt,
	); err != nil {
		return nil, 0, err
	}

	return &ticket, total, nil
}

func applyOptionalTicketValues(
	ticket *models.Ticket,
	brigadeID sql.NullString,
	assetID sql.NullString,
	incidentID sql.NullString,
	externalSystemID sql.NullString,
	externalID sql.NullString,
	assignedAt sql.NullTime,
	completedAt sql.NullTime,
	canceledAt sql.NullTime,
) error {
	optionalUUIDs := []struct {
		value  sql.NullString
		target **uuid.UUID
	}{
		{value: brigadeID, target: &ticket.BrigadeID},
		{value: assetID, target: &ticket.AssetID},
		{value: incidentID, target: &ticket.IncidentID},
		{value: externalSystemID, target: &ticket.ExternalSystemID},
	}

	for _, optional := range optionalUUIDs {

		if !optional.value.Valid {
			continue
		}

		parsed, err := uuid.Parse(optional.value.String)

		if err != nil {
			return err
		}

		*optional.target = &parsed
	}

	if externalID.Valid {
		ticket.ExternalID = &externalID.String
	}

	if assignedAt.Valid {
		ticket.AssignedAt = &assignedAt.Time
	}

	if completedAt.Valid {
		ticket.CompletedAt = &completedAt.Time
	}

	if canceledAt.Valid {
		ticket.CanceledAt = &canceledAt.Time
	}

	return nil
}
