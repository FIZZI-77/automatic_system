package service

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"notification/models"
)

type queryStore struct {
	store
	ctx  context.Context
	args []any
	err  error
}

func (r *queryStore) record(c context.Context, args ...any) { r.ctx = c; r.args = args }
func (r *queryStore) List(c context.Context, u uuid.UUID, x *bool, l, o int32) ([]*models.Notification, int64, int64, error) {
	r.record(c, u, x, l, o)
	return []*models.Notification{{UserID: u}}, 7, 2, r.err
}
func (r *queryStore) MarkRead(c context.Context, u, id uuid.UUID) (*models.Notification, error) {
	r.record(c, u, id)
	return &models.Notification{ID: id, UserID: u}, r.err
}
func (r *queryStore) MarkAllRead(c context.Context, u uuid.UUID) (int64, error) {
	r.record(c, u)
	return 7, r.err
}
func (r *queryStore) GetPreferences(c context.Context, u uuid.UUID) (*models.Preferences, error) {
	r.record(c, u)
	return &models.Preferences{UserID: u}, r.err
}
func (r *queryStore) SavePreferences(c context.Context, v *models.Preferences) (*models.Preferences, error) {
	r.record(c, v)
	return v, r.err
}
func (r *queryStore) DeleteDevice(c context.Context, u, id uuid.UUID) (*models.Device, error) {
	r.record(c, u, id)
	return &models.Device{ID: id, UserID: u}, r.err
}
func (r *queryStore) ListTemplates(c context.Context, e, ch *string, l, o int32) ([]*models.Template, int64, error) {
	r.record(c, e, ch, l, o)
	return []*models.Template{{EventType: *e}}, 7, r.err
}
func (r *queryStore) ListDeliveries(c context.Context, st, ch *string, l, o int32) ([]*models.Delivery, int64, error) {
	r.record(c, st, ch, l, o)
	return []*models.Delivery{{Status: *st}}, 7, r.err
}

func TestNotificationQueryContracts(t *testing.T) {
	t.Parallel()
	user, id := uuid.New(), uuid.New()
	unread := true
	event, channel, state := "ticket.created", "IN_APP", "PENDING"
	pref := &models.Preferences{UserID: user, InApp: true, Email: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, wantErr := range []error{nil, context.DeadlineExceeded} {
		r := &queryStore{err: wantErr}
		s := New(r, nil)
		for _, tt := range []struct {
			name string
			args []any
			call func() (bool, error)
		}{
			{"list", []any{user, &unread, int32(7), int32(3)}, func() (bool, error) {
				v, n, u, e := s.List(ctx, user, &unread, 7, 3)
				return len(v) == 1 && v[0].UserID == user && n == 7 && u == 2, e
			}},
			{"mark read", []any{user, id}, func() (bool, error) {
				v, e := s.MarkRead(ctx, user, id)
				return v != nil && v.UserID == user && v.ID == id, e
			}},
			{"mark all read", []any{user}, func() (bool, error) { n, e := s.MarkAllRead(ctx, user); return n == 7, e }},
			{"get preferences", []any{user}, func() (bool, error) { v, e := s.GetPreferences(ctx, user); return v != nil && v.UserID == user, e }},
			{"save preferences", []any{pref}, func() (bool, error) { v, e := s.SavePreferences(ctx, pref); return v == pref, e }},
			{"delete device", []any{user, id}, func() (bool, error) {
				v, e := s.DeleteDevice(ctx, user, id)
				return v != nil && v.UserID == user && v.ID == id, e
			}},
			{"templates", []any{&event, &channel, int32(7), int32(3)}, func() (bool, error) {
				v, n, e := s.ListTemplates(ctx, &event, &channel, 7, 3)
				return len(v) == 1 && v[0].EventType == event && n == 7, e
			}},
			{"deliveries", []any{&state, &channel, int32(7), int32(3)}, func() (bool, error) {
				v, n, e := s.ListDeliveries(ctx, &state, &channel, 7, 3)
				return len(v) == 1 && v[0].Status == state && n == 7, e
			}},
		} {
			ok, err := tt.call()
			if !ok || !errors.Is(err, wantErr) || r.ctx != ctx || !reflect.DeepEqual(r.args, tt.args) {
				t.Errorf("%s = valid %v, err %v args %v; want valid, %v args %v and original context", tt.name, ok, err, r.args, wantErr, tt.args)
			}
		}
	}
	for _, storageErr := range []error{pgx.ErrNoRows, fmt.Errorf("wrapped: %w", pgx.ErrNoRows)} {
		s := New(&queryStore{err: storageErr}, nil)
		if _, err := s.MarkRead(ctx, user, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("MarkRead(no rows) = %v; want not found", err)
		}
		if _, err := s.DeleteDevice(ctx, user, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteDevice(no rows) = %v; want not found", err)
		}
	}
}
