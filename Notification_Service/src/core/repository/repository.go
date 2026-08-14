package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"notification/models"
	"strings"
	"time"
)

type Repository struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }
func (r *Repository) List(ctx context.Context, user uuid.UUID, unread *bool, limit, offset int32) ([]*models.Notification, int64, int64, error) {
	limit = bounded(limit)
	rows, e := r.db.Query(ctx, `SELECT id,event_id,user_id,event_type,title,body,data,read,read_at,created_at,count(*) OVER(),count(*) FILTER(WHERE NOT read) OVER() FROM notifications WHERE user_id=$1 AND ($2::bool IS NULL OR read<>$2) ORDER BY created_at DESC LIMIT $3 OFFSET $4`, user, unread, limit, offset)
	if e != nil {
		return nil, 0, 0, e
	}
	defer rows.Close()
	var out []*models.Notification
	var total, unreadCount int64
	for rows.Next() {
		v := new(models.Notification)
		var data []byte
		if e = rows.Scan(&v.ID, &v.EventID, &v.UserID, &v.EventType, &v.Title, &v.Body, &data, &v.Read, &v.ReadAt, &v.CreatedAt, &total, &unreadCount); e != nil {
			return nil, 0, 0, e
		}
		_ = json.Unmarshal(data, &v.Data)
		out = append(out, v)
	}
	return out, total, unreadCount, rows.Err()
}
func (r *Repository) MarkRead(ctx context.Context, user, id uuid.UUID) (*models.Notification, error) {
	row := r.db.QueryRow(ctx, `UPDATE notifications SET read=true,read_at=COALESCE(read_at,now()) WHERE id=$1 AND user_id=$2 RETURNING id,event_id,user_id,event_type,title,body,data,read,read_at,created_at`, id, user)
	return scanNotification(row)
}
func (r *Repository) MarkAllRead(ctx context.Context, user uuid.UUID) (int64, error) {
	tag, e := r.db.Exec(ctx, `UPDATE notifications SET read=true,read_at=now() WHERE user_id=$1 AND NOT read`, user)
	return tag.RowsAffected(), e
}
func scanNotification(row pgx.Row) (*models.Notification, error) {
	v := new(models.Notification)
	var data []byte
	e := row.Scan(&v.ID, &v.EventID, &v.UserID, &v.EventType, &v.Title, &v.Body, &data, &v.Read, &v.ReadAt, &v.CreatedAt)
	_ = json.Unmarshal(data, &v.Data)
	return v, e
}
func (r *Repository) GetPreferences(ctx context.Context, user uuid.UUID) (*models.Preferences, error) {
	v := new(models.Preferences)
	e := r.db.QueryRow(ctx, `INSERT INTO notification_preferences(user_id) VALUES($1) ON CONFLICT(user_id) DO UPDATE SET user_id=EXCLUDED.user_id RETURNING user_id,in_app_enabled,push_enabled,email_enabled,sms_enabled,email,phone,updated_at`, user).Scan(&v.UserID, &v.InApp, &v.Push, &v.Email, &v.SMS, &v.EmailAddress, &v.Phone, &v.UpdatedAt)
	return v, e
}
func (r *Repository) SavePreferences(ctx context.Context, v *models.Preferences) (*models.Preferences, error) {
	e := r.db.QueryRow(ctx, `INSERT INTO notification_preferences(user_id,in_app_enabled,push_enabled,email_enabled,sms_enabled,email,phone) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id) DO UPDATE SET in_app_enabled=$2,push_enabled=$3,email_enabled=$4,sms_enabled=$5,email=$6,phone=$7,updated_at=now() RETURNING updated_at`, v.UserID, v.InApp, v.Push, v.Email, v.SMS, v.EmailAddress, v.Phone).Scan(&v.UpdatedAt)
	return v, e
}
func (r *Repository) RegisterDevice(ctx context.Context, v *models.Device) (*models.Device, error) {
	e := r.db.QueryRow(ctx, `INSERT INTO devices(user_id,token,platform) VALUES($1,$2,$3) ON CONFLICT(token) DO UPDATE SET user_id=$1,platform=$3,active=true,updated_at=now() RETURNING id,active,created_at,updated_at`, v.UserID, v.Token, v.Platform).Scan(&v.ID, &v.Active, &v.CreatedAt, &v.UpdatedAt)
	return v, e
}
func (r *Repository) DeleteDevice(ctx context.Context, user, id uuid.UUID) (*models.Device, error) {
	v := new(models.Device)
	e := r.db.QueryRow(ctx, `UPDATE devices SET active=false,updated_at=now() WHERE id=$1 AND user_id=$2 RETURNING id,user_id,token,platform,active,created_at,updated_at`, id, user).Scan(&v.ID, &v.UserID, &v.Token, &v.Platform, &v.Active, &v.CreatedAt, &v.UpdatedAt)
	return v, e
}
func (r *Repository) UpsertTemplate(ctx context.Context, v *models.Template) (*models.Template, error) {
	e := r.db.QueryRow(ctx, `INSERT INTO notification_templates(event_type,channel,subject,body,active) VALUES($1,$2,$3,$4,$5) ON CONFLICT(event_type,channel) DO UPDATE SET subject=$3,body=$4,active=$5,updated_at=now() RETURNING id,created_at,updated_at`, v.EventType, v.Channel, v.Subject, v.Body, v.Active).Scan(&v.ID, &v.CreatedAt, &v.UpdatedAt)
	return v, e
}
func (r *Repository) ListTemplates(ctx context.Context, event, channel *string, limit, offset int32) ([]*models.Template, int64, error) {
	rows, e := r.db.Query(ctx, `SELECT id,event_type,channel,subject,body,active,created_at,updated_at,count(*) OVER() FROM notification_templates WHERE ($1::text IS NULL OR event_type=$1) AND ($2::text IS NULL OR channel=$2) ORDER BY event_type,channel LIMIT $3 OFFSET $4`, event, channel, bounded(limit), offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []*models.Template
	var total int64
	for rows.Next() {
		v := new(models.Template)
		if e = rows.Scan(&v.ID, &v.EventType, &v.Channel, &v.Subject, &v.Body, &v.Active, &v.CreatedAt, &v.UpdatedAt, &total); e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}
func (r *Repository) ListDeliveries(ctx context.Context, status, channel *string, limit, offset int32) ([]*models.Delivery, int64, error) {
	rows, e := r.db.Query(ctx, `SELECT id,notification_id,channel,recipient,status,provider_id,attempts,next_attempt_at,last_error,created_at,updated_at,count(*) OVER() FROM deliveries WHERE ($1::text IS NULL OR status=$1) AND ($2::text IS NULL OR channel=$2) ORDER BY created_at DESC LIMIT $3 OFFSET $4`, status, channel, bounded(limit), offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []*models.Delivery
	var total int64
	for rows.Next() {
		v := new(models.Delivery)
		if e = rows.Scan(&v.ID, &v.NotificationID, &v.Channel, &v.Recipient, &v.Status, &v.ProviderID, &v.Attempts, &v.NextAttemptAt, &v.LastError, &v.CreatedAt, &v.UpdatedAt, &total); e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}
func (r *Repository) Dispatch(ctx context.Context, e models.Event, recipients []uuid.UUID) ([]*models.Notification, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	payload, _ := json.Marshal(e.Payload)
	tag, err := tx.Exec(ctx, `INSERT INTO event_inbox(event_id,event_type,topic,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, e.ID, e.Type, e.Topic, payload)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, tx.Commit(ctx)
	}
	var created []*models.Notification
	for _, user := range recipients {
		pref := models.Preferences{UserID: user, InApp: true, Push: true, Email: true}
		_ = tx.QueryRow(ctx, `SELECT in_app_enabled,push_enabled,email_enabled,sms_enabled,email,phone FROM notification_preferences WHERE user_id=$1`, user).Scan(&pref.InApp, &pref.Push, &pref.Email, &pref.SMS, &pref.EmailAddress, &pref.Phone)
		title, body := renderTemplate(ctx, tx, e.Type, "IN_APP", e.Payload)
		v := &models.Notification{EventID: e.ID, UserID: user, EventType: e.Type, Title: title, Body: body, Data: safeData(e.Payload)}
		data, _ := json.Marshal(v.Data)
		err = tx.QueryRow(ctx, `INSERT INTO notifications(event_id,user_id,event_type,title,body,data) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(event_id,user_id) DO NOTHING RETURNING id,created_at`, v.EventID, v.UserID, v.EventType, v.Title, v.Body, data).Scan(&v.ID, &v.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		created = append(created, v)
		if pref.InApp {
			_, err = tx.Exec(ctx, `INSERT INTO deliveries(notification_id,channel,recipient) VALUES($1,'IN_APP',$2) ON CONFLICT DO NOTHING`, v.ID, user.String())
		}
		if err == nil && pref.Email && pref.EmailAddress != nil {
			_, err = tx.Exec(ctx, `INSERT INTO deliveries(notification_id,channel,recipient) VALUES($1,'EMAIL',$2) ON CONFLICT DO NOTHING`, v.ID, *pref.EmailAddress)
		}
		if err == nil && pref.SMS && pref.Phone != nil {
			_, err = tx.Exec(ctx, `INSERT INTO deliveries(notification_id,channel,recipient) VALUES($1,'SMS',$2) ON CONFLICT DO NOTHING`, v.ID, *pref.Phone)
		}
		if err == nil && pref.Push {
			_, err = tx.Exec(ctx, `INSERT INTO deliveries(notification_id,channel,recipient) SELECT $1,'PUSH',token FROM devices WHERE user_id=$2 AND active ON CONFLICT DO NOTHING`, v.ID, user)
		}
		if err != nil {
			return nil, err
		}
	}
	return created, tx.Commit(ctx)
}
func renderTemplate(ctx context.Context, tx pgx.Tx, event, channel string, data map[string]any) (string, string) {
	var subject, body string
	err := tx.QueryRow(ctx, `SELECT subject,body FROM notification_templates WHERE event_type=$1 AND channel=$2 AND active`, event, channel).Scan(&subject, &body)
	if err != nil {
		subject = event
		body = "Событие " + event
	}
	for k, v := range data {
		value, ok := v.(string)
		if ok {
			subject = strings.ReplaceAll(subject, "{{"+k+"}}", value)
			body = strings.ReplaceAll(body, "{{"+k+"}}", value)
		}
	}
	return subject, body
}
func (r *Repository) ResolveRecipients(ctx context.Context, e models.Event) ([]uuid.UUID, error) {
	unique := map[uuid.UUID]struct{}{}
	for _, key := range []string{"user_id", "owner_user_id", "assigned_user_id"} {
		if raw, ok := e.Payload[key].(string); ok {
			if id, err := uuid.Parse(raw); err == nil {
				unique[id] = struct{}{}
			}
		}
	}
	ticketID, _ := uuid.Parse(stringValue(e.Payload, "ticket_id", "id"))
	if ticketID != uuid.Nil {
		if e.Topic == "tickets.events.v1" {
			userID, _ := uuid.Parse(stringValue(e.Payload, "user_id"))
			departmentID, _ := uuid.Parse(stringValue(e.Payload, "department_id"))
			brigadeID, _ := uuid.Parse(stringValue(e.Payload, "brigade_id"))
			_, err := r.db.Exec(ctx, `INSERT INTO ticket_recipients(ticket_id,user_id,department_id,brigade_id) VALUES($1,NULLIF($2::uuid,$5::uuid),NULLIF($3::uuid,$5::uuid),NULLIF($4::uuid,$5::uuid)) ON CONFLICT(ticket_id) DO UPDATE SET user_id=COALESCE(EXCLUDED.user_id,ticket_recipients.user_id),department_id=COALESCE(EXCLUDED.department_id,ticket_recipients.department_id),brigade_id=COALESCE(EXCLUDED.brigade_id,ticket_recipients.brigade_id),updated_at=now()`, ticketID, userID, departmentID, brigadeID, uuid.Nil)
			if err != nil {
				return nil, err
			}
		}
		var userID *uuid.UUID
		if err := r.db.QueryRow(ctx, `SELECT user_id FROM ticket_recipients WHERE ticket_id=$1`, ticketID).Scan(&userID); err == nil && userID != nil {
			unique[*userID] = struct{}{}
		}
	}
	out := make([]uuid.UUID, 0, len(unique))
	for id := range unique {
		out = append(out, id)
	}
	return out, nil
}
func stringValue(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := data[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
func (r *Repository) ClaimDelivery(ctx context.Context) (*models.Delivery, *models.Notification, error) {
	tx, e := r.db.Begin(ctx)
	if e != nil {
		return nil, nil, e
	}
	defer tx.Rollback(ctx)
	d := new(models.Delivery)
	e = tx.QueryRow(ctx, `SELECT id,notification_id,channel,recipient,status,provider_id,attempts,next_attempt_at,last_error,created_at,updated_at FROM deliveries WHERE status IN('PENDING','FAILED') AND next_attempt_at<=now() AND attempts<8 ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&d.ID, &d.NotificationID, &d.Channel, &d.Recipient, &d.Status, &d.ProviderID, &d.Attempts, &d.NextAttemptAt, &d.LastError, &d.CreatedAt, &d.UpdatedAt)
	if e != nil {
		return nil, nil, e
	}
	_, e = tx.Exec(ctx, `UPDATE deliveries SET status='PROCESSING',attempts=attempts+1,locked_at=now(),updated_at=now() WHERE id=$1`, d.ID)
	if e != nil {
		return nil, nil, e
	}
	n, e := scanNotification(tx.QueryRow(ctx, `SELECT id,event_id,user_id,event_type,title,body,data,read,read_at,created_at FROM notifications WHERE id=$1`, d.NotificationID))
	if e != nil {
		return nil, nil, e
	}
	d.Attempts++
	return d, n, tx.Commit(ctx)
}
func (r *Repository) DeliverySent(ctx context.Context, id uuid.UUID, provider string) error {
	_, e := r.db.Exec(ctx, `UPDATE deliveries SET status='SENT',provider_id=NULLIF($2,''),last_error=NULL,locked_at=NULL,updated_at=now() WHERE id=$1`, id, provider)
	return e
}
func (r *Repository) DeliveryFailed(ctx context.Context, d *models.Delivery, reason string) error {
	status := "FAILED"
	if d.Attempts >= 8 {
		status = "DEAD"
	}
	delay := time.Duration(1<<min(d.Attempts, 8)) * time.Second
	_, e := r.db.Exec(ctx, `UPDATE deliveries SET status=$2,last_error=$3,next_attempt_at=now()+make_interval(secs=>$4),locked_at=NULL,updated_at=now() WHERE id=$1`, d.ID, status, truncate(reason, 2000), delay.Seconds())
	return e
}
func (r *Repository) DeactivateToken(ctx context.Context, token string) error {
	_, e := r.db.Exec(ctx, `UPDATE devices SET active=false,updated_at=now() WHERE token=$1`, token)
	return e
}
func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}
func safeData(v map[string]any) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"ticket_id", "ticket_sla_id", "department_id", "status", "event_type"} {
		if s, ok := v[k].(string); ok {
			out[k] = s
		}
	}
	return out
}
func bounded(v int32) int32 {
	if v <= 0 {
		return 50
	}
	if v > 200 {
		return 200
	}
	return v
}
