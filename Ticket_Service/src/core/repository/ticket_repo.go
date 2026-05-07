package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"strings"
	"ticket/models"
	"time"
)

type TicketRepoStruct struct {
	db *sql.DB
}

func NewTicketRepository(db *sql.DB) *TicketRepoStruct {
	return &TicketRepoStruct{
		db: db,
	}
}

var ErrNotFound = errors.New("not found")

type ticketCreatedEventPayload struct {
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	TicketID     string    `json:"ticket_id"`
	DepartmentID string    `json:"department_id"`
	CategoryID   string    `json:"category_id"`
	UserID       string    `json:"user_id"`
	Priority     string    `json:"priority"`
	Status       string    `json:"status"`
	Address      string    `json:"address"`
	Latitude     float64   `json:"latitude"`
	Longitude    float64   `json:"longitude"`
	CreatedAt    time.Time `json:"created_at"`
}

func (t *TicketRepoStruct) CreateTicket(ctx context.Context, in models.CreateTicketInput) (*models.Ticket, error) {

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateTicket(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	categoryActive, err := t.isCategoryActive(ctx, tx, in.CategoryID)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateTicket(): check category: %w", err)
	}

	if !categoryActive {
		return nil, fmt.Errorf("repository: CreateTicket(): category is not active")
	}

	ticketID := uuid.NewString()
	now := time.Now().UTC()

	ticket, err := t.insertTicket(ctx, tx, ticketID, now, in)
	if err != nil {
		return nil, fmt.Errorf("repository: CreateTicket(): insert ticket: %w", err)
	}

	if err = t.insertTicketStatusHistory(
		ctx,
		tx,
		ticket.ID,
		"",
		models.TicketStatusNew,
		in.UserID,
		"Ticket created",
	); err != nil {
		return nil, fmt.Errorf("repository: CreateTicket(): insert status history: %w", err)
	}

	if err = t.insertTicketCreatedOutboxEvent(ctx, tx, ticket); err != nil {
		return nil, fmt.Errorf("repository: CreateTicket(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: CreateTicket(): commit: %w", err)
	}

	return ticket, nil
}

func (t *TicketRepoStruct) isCategoryActive(ctx context.Context, tx *sql.Tx, categoryID string) (bool, error) {
	const query = `
		SELECT is_active
		FROM ticket_categories
		WHERE id = $1
	`

	var isActive bool

	err := tx.QueryRowContext(ctx, query, categoryID).Scan(&isActive)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}

	if err != nil {
		return false, err
	}

	return isActive, nil
}

func (t *TicketRepoStruct) insertTicket(
	ctx context.Context,
	tx *sql.Tx,
	ticketID string,
	now time.Time,
	in models.CreateTicketInput,
) (*models.Ticket, error) {
	const query = `
		INSERT INTO tickets (
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
			canceled_at
		)
		VALUES (
			$1, $2, $3, $4, NULL,
			$5, $6, $7, $8,
			$9, $10, $11,
			$12, $13,
			NULL, NULL, NULL
		)
		RETURNING
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
			canceled_at
	`

	row := tx.QueryRowContext(
		ctx,
		query,
		ticketID,
		in.DepartmentID,
		in.CategoryID,
		in.UserID,
		in.Title,
		in.Description,
		models.TicketStatusNew,
		in.Priority,
		in.Address,
		in.Latitude,
		in.Longitude,
		now,
		now,
	)

	return scanTicket(row)
}

func (t *TicketRepoStruct) insertTicketStatusHistory(
	ctx context.Context,
	tx *sql.Tx,
	ticketID string,
	oldStatus models.TicketStatus,
	newStatus models.TicketStatus,
	changedBy string,
	comment string,
) error {
	const query = `
		INSERT INTO ticket_status_history (
			id,
			ticket_id,
			old_status,
			new_status,
			changed_by,
			comment,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, now())
	`

	var oldStatusValue any
	if oldStatus == "" {
		oldStatusValue = nil
	} else {
		oldStatusValue = string(oldStatus)
	}

	_, err := tx.ExecContext(
		ctx,
		query,
		uuid.NewString(),
		ticketID,
		oldStatusValue,
		string(newStatus),
		changedBy,
		comment,
	)

	return err
}

func (t *TicketRepoStruct) insertTicketCreatedOutboxEvent(
	ctx context.Context,
	tx *sql.Tx,
	ticket *models.Ticket,
) error {
	eventID := uuid.NewString()

	payload := ticketCreatedEventPayload{
		EventID:      eventID,
		EventType:    "ticket.created",
		TicketID:     ticket.ID,
		DepartmentID: ticket.DepartmentID,
		CategoryID:   ticket.CategoryID,
		UserID:       ticket.UserID,
		Priority:     string(ticket.Priority),
		Status:       string(ticket.Status),
		Address:      ticket.Address,
		Latitude:     ticket.Latitude,
		Longitude:    ticket.Longitude,
		CreatedAt:    ticket.CreatedAt,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO outbox_events (
			id,
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			status,
			attempts,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, 0, now())
	`

	_, err = tx.ExecContext(
		ctx,
		query,
		eventID,
		"ticket",
		ticket.ID,
		"ticket.created",
		string(payloadBytes),
		"PENDING",
	)

	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanTicket(s scanner) (*models.Ticket, error) {
	var ticket models.Ticket

	var brigadeID sql.NullString
	var assignedAt sql.NullTime
	var completedAt sql.NullTime
	var canceledAt sql.NullTime

	err := s.Scan(
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
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if brigadeID.Valid {
		ticket.BrigadeID = &brigadeID.String
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

	return &ticket, nil
}

func (t *TicketRepoStruct) GetTicketByID(ctx context.Context, ticketID string) (*models.Ticket, error) {
	const query = `
		SELECT
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
			canceled_at
		FROM tickets
		WHERE id = $1
	`

	row := t.db.QueryRowContext(ctx, query, ticketID)

	ticket, err := scanTicket(row)
	if err != nil {
		return nil, fmt.Errorf("repository: GetTicketByID(): %w", err)
	}

	return ticket, nil
}

func (t *TicketRepoStruct) ListTickets(ctx context.Context, in models.ListTicketsInput) ([]*models.Ticket, int64, error) {
	whereParts := make([]string, 0)
	args := make([]any, 0)

	addWhere := func(condition string, value any) {
		args = append(args, value)
		whereParts = append(whereParts, fmt.Sprintf(condition, len(args)))
	}

	if in.DepartmentID != "" {
		addWhere("department_id = $%d", in.DepartmentID)
	}

	if in.UserID != "" {
		addWhere("user_id = $%d", in.UserID)
	}

	if in.BrigadeID != "" {
		addWhere("brigade_id = $%d", in.BrigadeID)
	}

	if in.CategoryID != "" {
		addWhere("category_id = $%d", in.CategoryID)
	}

	if in.Status != "" {
		addWhere("status = $%d", string(in.Status))
	}

	if in.Priority != "" {
		addWhere("priority = $%d", string(in.Priority))
	}

	if in.CreatedFrom != nil {
		addWhere("created_at >= $%d", *in.CreatedFrom)
	}

	if in.CreatedTo != nil {
		addWhere("created_at <= $%d", *in.CreatedTo)
	}

	whereSQL := ""
	if len(whereParts) > 0 {
		whereSQL = "WHERE " + strings.Join(whereParts, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM tickets
		%s
	`, whereSQL)

	var total int64
	if err := t.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("repository: ListTickets(): count: %w", err)
	}

	sortBy := ticketSortColumn(in.SortBy)
	sortOrder := ticketSortOrder(in.SortOrder)

	args = append(args, in.Limit, in.Offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	listQuery := fmt.Sprintf(`
		SELECT
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
			canceled_at
		FROM tickets
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereSQL, sortBy, sortOrder, limitArg, offsetArg)

	rows, err := t.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("repository: ListTickets(): query: %w", err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	tickets := make([]*models.Ticket, 0)

	for rows.Next() {
		ticket, err := scanTicket(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("repository: ListTickets(): scan: %w", err)
		}

		tickets = append(tickets, ticket)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository: ListTickets(): rows: %w", err)
	}

	return tickets, total, nil
}

func (t *TicketRepoStruct) UpdateTicket(ctx context.Context, in models.UpdateTicketInput) (*models.Ticket, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateTicket(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	setParts := make([]string, 0)
	args := make([]any, 0)

	addSet := func(column string, value any) {
		args = append(args, value)
		setParts = append(setParts, fmt.Sprintf("%s = $%d", column, len(args)))
	}

	if strings.TrimSpace(in.Title) != "" {
		addSet("title", in.Title)
	}

	if strings.TrimSpace(in.Description) != "" {
		addSet("description", in.Description)
	}

	if strings.TrimSpace(in.CategoryID) != "" {
		categoryActive, err := t.isCategoryActive(ctx, tx, in.CategoryID)
		if err != nil {
			return nil, fmt.Errorf("repository: UpdateTicket(): check category: %w", err)
		}

		if !categoryActive {
			return nil, fmt.Errorf("repository: UpdateTicket(): category is not active")
		}

		addSet("category_id", in.CategoryID)
	}

	if in.Priority != "" {
		addSet("priority", string(in.Priority))
	}

	if strings.TrimSpace(in.Address) != "" {
		addSet("address", in.Address)
	}

	if in.Latitude != nil && in.Longitude != nil {
		addSet("latitude", *in.Latitude)
		addSet("longitude", *in.Longitude)
	}

	addSet("updated_at", time.Now().UTC())

	args = append(args, in.TicketID)
	ticketIDArg := len(args)

	query := fmt.Sprintf(`
		UPDATE tickets
		SET %s
		WHERE id = $%d
		  AND status NOT IN ('DONE', 'CANCELED')
		RETURNING
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
			canceled_at
	`, strings.Join(setParts, ", "), ticketIDArg)

	row := tx.QueryRowContext(ctx, query, args...)

	ticket, err := scanTicket(row)
	if err != nil {
		return nil, fmt.Errorf("repository: UpdateTicket(): update ticket: %w", err)
	}

	if err = t.insertOutboxEvent(ctx, tx, "ticket", ticket.ID, "ticket.updated", ticket); err != nil {
		return nil, fmt.Errorf("repository: UpdateTicket(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: UpdateTicket(): commit: %w", err)
	}

	return ticket, nil
}

func (t *TicketRepoStruct) ChangeTicketStatus(ctx context.Context, in models.ChangeTicketStatusInput) (*models.Ticket, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: ChangeTicketStatus(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	oldTicket, err := t.getTicketByIDForUpdate(ctx, tx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("repository: ChangeTicketStatus(): get ticket: %w", err)
	}

	const query = `
		UPDATE tickets
		SET status = $1,
		    updated_at = now()
		WHERE id = $2
		RETURNING
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
			canceled_at
	`

	row := tx.QueryRowContext(ctx, query, string(in.NewStatus), in.TicketID)

	ticket, err := scanTicket(row)
	if err != nil {
		return nil, fmt.Errorf("repository: ChangeTicketStatus(): update ticket: %w", err)
	}

	if err = t.insertTicketStatusHistory(ctx, tx, ticket.ID, oldTicket.Status, in.NewStatus, in.ChangedBy, in.Comment); err != nil {
		return nil, fmt.Errorf("repository: ChangeTicketStatus(): insert status history: %w", err)
	}

	if err = t.insertOutboxEvent(ctx, tx, "ticket", ticket.ID, "ticket.status_changed", ticket); err != nil {
		return nil, fmt.Errorf("repository: ChangeTicketStatus(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: ChangeTicketStatus(): commit: %w", err)
	}

	return ticket, nil
}

func (t *TicketRepoStruct) AssignBrigade(ctx context.Context, in models.AssignBrigadeInput) (*models.Ticket, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: AssignBrigade(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	oldTicket, err := t.getTicketByIDForUpdate(ctx, tx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("repository: AssignBrigade(): get ticket: %w", err)
	}

	const query = `
		UPDATE tickets
		SET brigade_id = $1,
		    status = $2,
		    assigned_at = now(),
		    updated_at = now()
		WHERE id = $3
		  AND status NOT IN ('DONE', 'CANCELED')
		RETURNING
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
			canceled_at
	`

	row := tx.QueryRowContext(ctx, query, in.BrigadeID, string(models.TicketStatusAssigned), in.TicketID)

	ticket, err := scanTicket(row)
	if err != nil {
		return nil, fmt.Errorf("repository: AssignBrigade(): update ticket: %w", err)
	}

	if err = t.insertTicketStatusHistory(ctx, tx, ticket.ID, oldTicket.Status, models.TicketStatusAssigned, in.AssignedBy, in.Comment); err != nil {
		return nil, fmt.Errorf("repository: AssignBrigade(): insert status history: %w", err)
	}

	if err = t.insertOutboxEvent(ctx, tx, "ticket", ticket.ID, "ticket.assigned", ticket); err != nil {
		return nil, fmt.Errorf("repository: AssignBrigade(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: AssignBrigade(): commit: %w", err)
	}

	return ticket, nil
}

func (t *TicketRepoStruct) CancelTicket(ctx context.Context, in models.CancelTicketInput) (*models.Ticket, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: CancelTicket(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	oldTicket, err := t.getTicketByIDForUpdate(ctx, tx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("repository: CancelTicket(): get ticket: %w", err)
	}

	const query = `
		UPDATE tickets
		SET status = $1,
		    canceled_at = now(),
		    updated_at = now()
		WHERE id = $2
		  AND status NOT IN ('DONE', 'CANCELED')
		RETURNING
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
			canceled_at
	`

	row := tx.QueryRowContext(ctx, query, string(models.TicketStatusCanceled), in.TicketID)

	ticket, err := scanTicket(row)
	if err != nil {
		return nil, fmt.Errorf("repository: CancelTicket(): update ticket: %w", err)
	}

	if err = t.insertTicketStatusHistory(ctx, tx, ticket.ID, oldTicket.Status, models.TicketStatusCanceled, in.CanceledBy, in.Reason); err != nil {
		return nil, fmt.Errorf("repository: CancelTicket(): insert status history: %w", err)
	}

	if err = t.insertOutboxEvent(ctx, tx, "ticket", ticket.ID, "ticket.canceled", ticket); err != nil {
		return nil, fmt.Errorf("repository: CancelTicket(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: CancelTicket(): commit: %w", err)
	}

	return ticket, nil
}

func (t *TicketRepoStruct) CompleteTicket(ctx context.Context, in models.CompleteTicketInput) (*models.Ticket, error) {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("repository: CompleteTicket(): begin tx: %w", err)
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {

		}
	}(tx)

	oldTicket, err := t.getTicketByIDForUpdate(ctx, tx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("repository: CompleteTicket(): get ticket: %w", err)
	}

	const query = `
		UPDATE tickets
		SET status = $1,
		    completed_at = now(),
		    updated_at = now()
		WHERE id = $2
		  AND status NOT IN ('DONE', 'CANCELED')
		RETURNING
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
			canceled_at
	`

	row := tx.QueryRowContext(ctx, query, string(models.TicketStatusDone), in.TicketID)

	ticket, err := scanTicket(row)
	if err != nil {
		return nil, fmt.Errorf("repository: CompleteTicket(): update ticket: %w", err)
	}

	if err = t.insertTicketStatusHistory(ctx, tx, ticket.ID, oldTicket.Status, models.TicketStatusDone, in.CompletedBy, in.Comment); err != nil {
		return nil, fmt.Errorf("repository: CompleteTicket(): insert status history: %w", err)
	}

	if err = t.insertOutboxEvent(ctx, tx, "ticket", ticket.ID, "ticket.completed", ticket); err != nil {
		return nil, fmt.Errorf("repository: CompleteTicket(): insert outbox event: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("repository: CompleteTicket(): commit: %w", err)
	}

	return ticket, nil
}

func (t *TicketRepoStruct) GetTicketStatusHistory(ctx context.Context, in models.GetTicketStatusHistoryInput) ([]*models.TicketStatusHistory, int64, error) {
	const countQuery = `
		SELECT COUNT(*)
		FROM ticket_status_history
		WHERE ticket_id = $1
	`

	var total int64
	if err := t.db.QueryRowContext(ctx, countQuery, in.TicketID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("repository: GetTicketStatusHistory(): count: %w", err)
	}

	const listQuery = `
		SELECT
			id,
			ticket_id,
			old_status,
			new_status,
			changed_by,
			comment,
			created_at
		FROM ticket_status_history
		WHERE ticket_id = $1
		ORDER BY created_at ASC
		LIMIT $2 OFFSET $3
	`

	rows, err := t.db.QueryContext(ctx, listQuery, in.TicketID, in.Limit, in.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository: GetTicketStatusHistory(): query: %w", err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	history := make([]*models.TicketStatusHistory, 0)

	for rows.Next() {
		item, err := scanTicketStatusHistory(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("repository: GetTicketStatusHistory(): scan: %w", err)
		}

		history = append(history, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository: GetTicketStatusHistory(): rows: %w", err)
	}

	return history, total, nil
}

func (t *TicketRepoStruct) getTicketByIDForUpdate(ctx context.Context, tx *sql.Tx, ticketID string) (*models.Ticket, error) {
	const query = `
		SELECT
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
			canceled_at
		FROM tickets
		WHERE id = $1
		FOR UPDATE
	`

	row := tx.QueryRowContext(ctx, query, ticketID)

	ticket, err := scanTicket(row)
	if err != nil {
		return nil, err
	}

	return ticket, nil
}

func (t *TicketRepoStruct) insertOutboxEvent(
	ctx context.Context,
	tx *sql.Tx,
	aggregateType string,
	aggregateID string,
	eventType string,
	payload any,
) error {
	eventID := uuid.NewString()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO outbox_events (
			id,
			aggregate_type,
			aggregate_id,
			event_type,
			payload,
			status,
			attempts,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'PENDING', 0, now())
	`

	_, err = tx.ExecContext(
		ctx,
		query,
		eventID,
		aggregateType,
		aggregateID,
		eventType,
		string(payloadBytes),
	)

	return err
}

func scanTicketStatusHistory(s scanner) (*models.TicketStatusHistory, error) {
	var item models.TicketStatusHistory

	var oldStatus sql.NullString
	var changedBy sql.NullString
	var comment sql.NullString

	err := s.Scan(
		&item.ID,
		&item.TicketID,
		&oldStatus,
		&item.NewStatus,
		&changedBy,
		&comment,
		&item.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if oldStatus.Valid {
		item.OldStatus = models.TicketStatus(oldStatus.String)
	}

	if changedBy.Valid {
		item.ChangedBy = changedBy.String
	}

	if comment.Valid {
		item.Comment = comment.String
	}

	return &item, nil
}

func ticketSortColumn(sortBy models.TicketSortBy) string {
	switch sortBy {
	case models.TicketSortByUpdatedAt:
		return "updated_at"
	case models.TicketSortByPriority:
		return "priority"
	case models.TicketSortByStatus:
		return "status"
	case models.TicketSortByCreatedAt:
		return "created_at"
	default:
		return "created_at"
	}
}

func ticketSortOrder(order models.SortOrder) string {
	switch order {
	case models.SortOrderAsc:
		return "ASC"
	case models.SortOrderDesc:
		return "DESC"
	default:
		return "DESC"
	}
}
