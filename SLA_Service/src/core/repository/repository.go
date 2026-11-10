package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"sla/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

// New создаёт хранилище правил, состояний и истории SLA с пулом db.
func New(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// CreateRule сохраняет правило, усекая длительности до целых секунд.
// Заполняет ID, активность и временные метки в v из базы и возвращает тот же указатель.
func (r *Repository) CreateRule(ctx context.Context, v *models.Rule) (*models.Rule, error) {
	err := r.db.QueryRow(ctx, `INSERT INTO sla_rules(name,department_id,category_id,priority,response_seconds,resolution_seconds,warning_percent) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,active,created_at,updated_at`, v.Name, v.DepartmentID, v.CategoryID, v.Priority, int64(v.ResponseTime/time.Second), int64(v.ResolutionTime/time.Second), v.WarningPercent).Scan(&v.ID, &v.Active, &v.CreatedAt, &v.UpdatedAt)
	return v, mapErr(err)
}

// GetRule возвращает правило по ID, включая неактивное; отсутствие даёт ErrNotFound.
func (r *Repository) GetRule(ctx context.Context, id uuid.UUID) (*models.Rule, error) {
	row := r.db.QueryRow(ctx, `SELECT id,name,department_id,category_id,priority,response_seconds,resolution_seconds,warning_percent,active,created_at,updated_at FROM sla_rules WHERE id=$1`, id)
	return scanRule(row)
}

// UpdateRule заменяет поля правила по v.ID, усекая длительности до целых секунд.
// Обновляет временные метки в v; отсутствие правила возвращает как ErrNotFound.
func (r *Repository) UpdateRule(ctx context.Context, v *models.Rule) (*models.Rule, error) {
	err := r.db.QueryRow(ctx, `UPDATE sla_rules SET name=$2,department_id=$3,category_id=$4,priority=$5,response_seconds=$6,resolution_seconds=$7,warning_percent=$8,active=$9,updated_at=now() WHERE id=$1 RETURNING created_at,updated_at`, v.ID, v.Name, v.DepartmentID, v.CategoryID, v.Priority, int64(v.ResponseTime/time.Second), int64(v.ResolutionTime/time.Second), v.WarningPercent, v.Active).Scan(&v.CreatedAt, &v.UpdatedAt)
	return v, mapErr(err)
}

// DeleteRule читает правило и сохраняет его с Active=false, возвращая результат.
// Физически строку не удаляет; отсутствие правила даёт ErrNotFound.
func (r *Repository) DeleteRule(ctx context.Context, id uuid.UUID) (*models.Rule, error) {
	v, e := r.GetRule(ctx, id)

	if e != nil {
		return nil, e
	}

	v.Active = false
	return r.UpdateRule(ctx, v)
}

// ListRules возвращает страницу правил по фильтрам от новых к старым и оконный
// общий счётчик. Нормализует лимит в копии f; пустая страница даёт nil и нулевой счётчик.
func (r *Repository) ListRules(ctx context.Context, f models.RuleFilter) ([]*models.Rule, int64, error) {
	f.Limit = limit(f.Limit)
	rows, e := r.db.Query(ctx, `SELECT id,name,department_id,category_id,priority,response_seconds,resolution_seconds,warning_percent,active,created_at,updated_at,count(*) OVER() FROM sla_rules WHERE ($1::uuid IS NULL OR department_id=$1) AND ($2::uuid IS NULL OR category_id=$2) AND ($3::text IS NULL OR priority=$3) AND ($4::bool IS NULL OR active=$4) ORDER BY created_at DESC LIMIT $5 OFFSET $6`, f.DepartmentID, f.CategoryID, f.Priority, f.Active, f.Limit, f.Offset)

	if e != nil {
		return nil, 0, e
	}

	defer rows.Close()

	var out []*models.Rule
	var total int64
	for rows.Next() {
		v := new(models.Rule)
		var rs, xs int64

		if e = rows.Scan(&v.ID, &v.Name, &v.DepartmentID, &v.CategoryID, &v.Priority, &rs, &xs, &v.WarningPercent, &v.Active, &v.CreatedAt, &v.UpdatedAt, &total); e != nil {
			return nil, 0, e
		}

		v.ResponseTime = time.Duration(rs) * time.Second
		v.ResolutionTime = time.Duration(xs) * time.Second
		out = append(out, v)
	}

	return out, total, rows.Err()
}

// MatchRule выбирает активное правило по ведомству, категории и приоритету,
// считая NULL универсальным условием. Предпочитает больше заданных условий,
// затем более позднее обновление; отсутствие совпадения даёт ErrNotFound.
func (r *Repository) MatchRule(ctx context.Context, d, c uuid.UUID, p models.Priority) (*models.Rule, error) {
	return scanRule(r.db.QueryRow(ctx, `SELECT id,name,department_id,category_id,priority,response_seconds,resolution_seconds,warning_percent,active,created_at,updated_at FROM sla_rules WHERE active AND (department_id IS NULL OR department_id=$1) AND (category_id IS NULL OR category_id=$2) AND (priority IS NULL OR priority=$3) ORDER BY (department_id IS NOT NULL)::int+(category_id IS NOT NULL)::int+(priority IS NOT NULL)::int DESC,updated_at DESC LIMIT 1`, d, c, p))
}

// scanRule читает правило и переводит секундные сроки в time.Duration.
// Возвращает выделенную модель вместе с преобразованной через mapErr ошибкой чтения.
func scanRule(row pgx.Row) (*models.Rule, error) {
	v := new(models.Rule)
	var a, b int64
	e := row.Scan(&v.ID, &v.Name, &v.DepartmentID, &v.CategoryID, &v.Priority, &a, &b, &v.WarningPercent, &v.Active, &v.CreatedAt, &v.UpdatedAt)
	v.ResponseTime = time.Duration(a) * time.Second
	v.ResolutionTime = time.Duration(b) * time.Second
	return v, mapErr(e)
}

// GetTicketSLA читает состояние SLA по ID заявки; отсутствие возвращает как ErrNotFound.
func (r *Repository) GetTicketSLA(ctx context.Context, id uuid.UUID) (*models.TicketSLA, error) {
	return scanSLA(r.db.QueryRow(ctx, slaSelect+` WHERE ticket_id=$1`, id))
}

const slaSelect = `SELECT id,ticket_id,rule_id,department_id,category_id,priority,status,ticket_created_at,response_deadline,resolution_deadline,responded_at,completed_at,response_breached,resolution_breached,response_warning_sent,resolution_warning_sent,version,created_at,updated_at FROM ticket_slas`

// scanSLA читает состояние SLA в порядке slaSelect и возвращает модель
// вместе с преобразованной через mapErr ошибкой чтения.
func scanSLA(row pgx.Row) (*models.TicketSLA, error) {
	v := new(models.TicketSLA)
	e := row.Scan(&v.ID, &v.TicketID, &v.RuleID, &v.DepartmentID, &v.CategoryID, &v.Priority, &v.Status, &v.TicketCreatedAt, &v.ResponseDeadline, &v.ResolutionDeadline, &v.RespondedAt, &v.CompletedAt, &v.ResponseBreached, &v.ResolutionBreached, &v.ResponseWarningSent, &v.ResolutionWarningSent, &v.Version, &v.CreatedAt, &v.UpdatedAt)
	return v, mapErr(e)
}

// ListSLAs возвращает страницу состояний SLA от новых к старым с фильтром ведомства,
// статуса и наличия любого нарушения. Нормализует лимит в копии f;
// на пустой странице возвращает nil и нулевой общий счётчик.
func (r *Repository) ListSLAs(ctx context.Context, f models.SLAFilter) ([]*models.TicketSLA, int64, error) {
	f.Limit = limit(f.Limit)
	query := strings.Replace(slaSelect, " FROM ticket_slas", ",count(*) OVER() FROM ticket_slas", 1)
	rows, e := r.db.Query(ctx, query+` WHERE ($1::uuid IS NULL OR department_id=$1) AND ($2::text IS NULL OR status=$2) AND ($3::bool IS NULL OR (response_breached OR resolution_breached)=$3) ORDER BY created_at DESC LIMIT $4 OFFSET $5`, f.DepartmentID, f.Status, f.Breached, f.Limit, f.Offset)

	if e != nil {
		return nil, 0, e
	}

	defer rows.Close()

	var out []*models.TicketSLA
	var total int64
	for rows.Next() {
		v := new(models.TicketSLA)
		e = rows.Scan(&v.ID, &v.TicketID, &v.RuleID, &v.DepartmentID, &v.CategoryID, &v.Priority, &v.Status, &v.TicketCreatedAt, &v.ResponseDeadline, &v.ResolutionDeadline, &v.RespondedAt, &v.CompletedAt, &v.ResponseBreached, &v.ResolutionBreached, &v.ResponseWarningSent, &v.ResolutionWarningSent, &v.Version, &v.CreatedAt, &v.UpdatedAt, &total)

		if e != nil {
			return nil, 0, e
		}

		out = append(out, v)
	}

	return out, total, rows.Err()
}

// ApplyEvent транзакционно записывает событие в inbox и создаёт либо меняет SLA
// вместе с историей и outbox. Повтор события пропускает; если SLA ещё нет и rule=nil,
// сохраняет только inbox. Для нового SLA отсчитывает сроки от времени создания заявки.
func (r *Repository) ApplyEvent(ctx context.Context, ev models.TicketEvent, rule *models.Rule) error {
	tx, e := r.db.Begin(ctx)

	if e != nil {
		return e
	}

	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `INSERT INTO ticket_event_inbox(event_id,event_type,ticket_id,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, ev.EventID, ev.EventType, ev.TicketID, mustJSON(ev))

	if e != nil {
		return e
	}

	if tag.RowsAffected() == 0 {
		return tx.Commit(ctx)
	}

	v, e := scanSLA(tx.QueryRow(ctx, slaSelect+` WHERE ticket_id=$1 FOR UPDATE`, ev.TicketID))

	if errors.Is(e, models.ErrNotFound) {

		if rule == nil {
			return tx.Commit(ctx)
		}

		ticketCreatedAt := ev.CreatedAt

		if ticketCreatedAt.IsZero() {
			ticketCreatedAt = ev.UpdatedAt
		}

		if ticketCreatedAt.IsZero() {
			ticketCreatedAt = time.Now().UTC()
		}

		v = &models.TicketSLA{
			ID:                 uuid.New(),
			TicketID:           ev.TicketID,
			RuleID:             rule.ID,
			DepartmentID:       ev.DepartmentID,
			CategoryID:         ev.CategoryID,
			Priority:           ev.Priority,
			Status:             models.StatusActive,
			TicketCreatedAt:    ticketCreatedAt,
			ResponseDeadline:   ticketCreatedAt.Add(rule.ResponseTime),
			ResolutionDeadline: ticketCreatedAt.Add(rule.ResolutionTime),
			Version:            1,
		}

		_, e = tx.Exec(ctx, `INSERT INTO ticket_slas(id,ticket_id,rule_id,department_id,category_id,priority,status,ticket_created_at,response_deadline,resolution_deadline,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, v.ID, v.TicketID, v.RuleID, v.DepartmentID, v.CategoryID, v.Priority, v.Status, v.TicketCreatedAt, v.ResponseDeadline, v.ResolutionDeadline, v.Version)

		if e == nil {
			e = history(ctx, tx, v, models.EventCreated, "ticket SLA created")
		}

		if e == nil && ev.EventType != "ticket.created" {
			e = transition(ctx, tx, v, ev, rule)
		}

	} else if e == nil {
		e = transition(ctx, tx, v, ev, rule)
	}

	if e != nil {
		return e
	}

	return tx.Commit(ctx)
}

// transition изменяет v по событию заявки: отмечает реакцию, завершение, отмену
// либо пересчитывает сроки при смене правила. Сохраняет v с увеличением версии в tx
// и добавляет историю и outbox для распознанного изменения.
func transition(ctx context.Context, tx pgx.Tx, v *models.TicketSLA, ev models.TicketEvent, rule *models.Rule) error {
	now := ev.UpdatedAt

	if now.IsZero() {
		now = time.Now().UTC()
	}

	kind := models.EventType("")
	details := ""
	switch ev.EventType {
	case "ticket.assigned", "ticket.status_changed":

		if ev.Status == "ASSIGNED" || ev.Status == "IN_PROGRESS" {

			if v.RespondedAt == nil {
				v.RespondedAt = &now
				v.ResponseBreached = now.After(v.ResponseDeadline)
				kind = models.EventResponseRecorded
				details = "ticket response recorded"
			}

		}

	case "ticket.completed":
		v.Status = models.StatusCompleted
		v.CompletedAt = &now
		v.ResolutionBreached = now.After(v.ResolutionDeadline)
		kind = models.EventCompleted
		details = "ticket completed"
	case "ticket.canceled":
		v.Status = models.StatusCancelled
		v.CompletedAt = &now
		kind = models.EventCancelled
		details = "ticket cancelled"
	case "ticket.updated":

		if rule != nil && rule.ID != v.RuleID {
			v.RuleID = rule.ID
			v.Priority = ev.Priority
			v.ResponseDeadline = v.TicketCreatedAt.Add(rule.ResponseTime)
			v.ResolutionDeadline = v.TicketCreatedAt.Add(rule.ResolutionTime)
			kind = models.EventRecalculated
			details = "SLA rule changed"
		}

	}

	_, e := tx.Exec(ctx, `UPDATE ticket_slas SET rule_id=$2,priority=$3,status=$4,response_deadline=$5,resolution_deadline=$6,responded_at=$7,completed_at=$8,response_breached=$9,resolution_breached=$10,version=version+1,updated_at=now() WHERE id=$1`, v.ID, v.RuleID, v.Priority, v.Status, v.ResponseDeadline, v.ResolutionDeadline, v.RespondedAt, v.CompletedAt, v.ResponseBreached, v.ResolutionBreached)

	if e == nil && kind != "" {
		e = history(ctx, tx, v, kind, details)
	}

	return e
}

// CheckDeadlines транзакционно проверяет активные SLA на момент now, пропуская
// заблокированные строки. Сохраняет новые признаки предупреждений и нарушений,
// увеличивает версию изменённых записей и добавляет историю с outbox.
func (r *Repository) CheckDeadlines(ctx context.Context, now time.Time) error {
	tx, e := r.db.Begin(ctx)

	if e != nil {
		return e
	}

	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, slaSelect+` WHERE status='ACTIVE' FOR UPDATE SKIP LOCKED`)

	if e != nil {
		return e
	}

	var items []*models.TicketSLA
	for rows.Next() {
		v, e := scanSLA(rows)

		if e != nil {
			rows.Close()
			return e
		}

		items = append(items, v)
	}
	rows.Close()

	for _, v := range items {
		rule, e := scanRule(tx.QueryRow(ctx, `SELECT id,name,department_id,category_id,priority,response_seconds,resolution_seconds,warning_percent,active,created_at,updated_at FROM sla_rules WHERE id=$1`, v.RuleID))

		if e != nil {
			return e
		}

		changed := false

		if v.RespondedAt == nil && !v.ResponseBreached && now.After(v.ResponseDeadline) {
			v.ResponseBreached = true
			changed = true
			e = history(ctx, tx, v, models.EventResponseBreached, "response deadline breached")
		} else if v.RespondedAt == nil && !v.ResponseWarningSent && warningReached(v.TicketCreatedAt, v.ResponseDeadline, rule.WarningPercent, now) {
			v.ResponseWarningSent = true
			changed = true
			e = history(ctx, tx, v, models.EventResponseWarning, "response deadline approaching")
		}

		if e != nil {
			return e
		}

		if !v.ResolutionBreached && now.After(v.ResolutionDeadline) {
			v.ResolutionBreached = true
			changed = true
			e = history(ctx, tx, v, models.EventResolutionBreached, "resolution deadline breached")
		} else if !v.ResolutionWarningSent && warningReached(v.TicketCreatedAt, v.ResolutionDeadline, rule.WarningPercent, now) {
			v.ResolutionWarningSent = true
			changed = true
			e = history(ctx, tx, v, models.EventResolutionWarning, "resolution deadline approaching")
		}

		if e != nil {
			return e
		}

		if changed {
			_, e = tx.Exec(ctx, `UPDATE ticket_slas SET response_breached=$2,resolution_breached=$3,response_warning_sent=$4,resolution_warning_sent=$5,version=version+1,updated_at=now() WHERE id=$1`, v.ID, v.ResponseBreached, v.ResolutionBreached, v.ResponseWarningSent, v.ResolutionWarningSent)

			if e != nil {
				return e
			}

		}

	}

	return tx.Commit(ctx)
}

// warningReached сообщает, наступил ли момент start + p процентов интервала до deadline.
// Равенство порогу считается достижением; входные значения не проверяет.
func warningReached(start, deadline time.Time, p int32, now time.Time) bool {
	return !now.Before(start.Add(time.Duration(float64(deadline.Sub(start)) * float64(p) / 100)))
}

// history записывает изменение SLA и одноимённое событие sla.<тип> в outbox через tx.
// Обе записи используют один UUID и текущее UTC-время; v не изменяется.
func history(ctx context.Context, tx pgx.Tx, v *models.TicketSLA, k models.EventType, d string) error {
	id := uuid.New()
	at := time.Now().UTC()
	_, e := tx.Exec(ctx, `INSERT INTO sla_history(id,ticket_sla_id,ticket_id,event_type,details,occurred_at) VALUES($1,$2,$3,$4,$5,$6)`, id, v.ID, v.TicketID, k, d, at)

	if e != nil {
		return e
	}

	payload := mustJSON(map[string]any{
		"event_id":            id,
		"event_type":          "sla." + string(k),
		"ticket_id":           v.TicketID,
		"ticket_sla_id":       v.ID,
		"department_id":       v.DepartmentID,
		"category_id":         v.CategoryID,
		"response_deadline":   v.ResponseDeadline,
		"resolution_deadline": v.ResolutionDeadline,
		"responded_at":        v.RespondedAt,
		"completed_at":        v.CompletedAt,
		"response_breached":   v.ResponseBreached,
		"resolution_breached": v.ResolutionBreached,
		"occurred_at":         at,
	})
	_, e = tx.Exec(ctx, `INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload) VALUES($1,'ticket_sla',$2,$3,$4)`, id, v.ID, "sla."+string(k), payload)
	return e
}

// ListHistory возвращает страницу истории SLA по ID заявки от новых событий к старым.
// Нормализует lim; на пустой странице возвращает nil и нулевой общий счётчик.
func (r *Repository) ListHistory(ctx context.Context, id uuid.UUID, lim, off int32) ([]*models.History, int64, error) {
	rows, e := r.db.Query(ctx, `SELECT id,ticket_sla_id,ticket_id,event_type,occurred_at,details,count(*) OVER() FROM sla_history WHERE ticket_id=$1 ORDER BY occurred_at DESC LIMIT $2 OFFSET $3`, id, limit(lim), off)

	if e != nil {
		return nil, 0, e
	}

	defer rows.Close()

	var out []*models.History
	var total int64
	for rows.Next() {
		v := new(models.History)

		if e = rows.Scan(&v.ID, &v.TicketSLAID, &v.TicketID, &v.EventType, &v.OccurredAt, &v.Details, &total); e != nil {
			return nil, 0, e
		}

		out = append(out, v)
	}

	return out, total, rows.Err()
}

// mustJSON сериализует v в JSON, игнорируя ошибку; при невозможности сериализации возвращает nil.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// limit возвращает лимит страницы: 50 для неположительного v и не больше 200.
func limit(v int32) int32 {

	if v <= 0 {
		return 50
	}

	if v > 200 {
		return 200
	}

	return v
}

// mapErr заменяет pgx.ErrNoRows на ErrNotFound, прочие ошибки оборачивает
// префиксом repository, а nil возвращает без изменений.
func mapErr(e error) error {

	if errors.Is(e, pgx.ErrNoRows) {
		return models.ErrNotFound
	}

	if e != nil {
		return fmt.Errorf("repository: %w", e)
	}

	return nil
}
