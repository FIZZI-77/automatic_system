package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"notification/models"
)

type dispatchStore struct {
	store
	users                   []uuid.UUID
	items                   []*models.Notification
	resolveErr, dispatchErr error
	resolved, dispatched    bool
	event                   models.Event
}

func (r *dispatchStore) ResolveRecipients(_ context.Context, e models.Event) ([]uuid.UUID, error) {
	r.resolved = true
	if !reflect.DeepEqual(e, r.event) {
		return nil, errors.New("wrong event")
	}
	return r.users, r.resolveErr
}
func (r *dispatchStore) Dispatch(_ context.Context, e models.Event, users []uuid.UUID) ([]*models.Notification, error) {
	r.dispatched = true
	if !reflect.DeepEqual(e, r.event) || !reflect.DeepEqual(users, r.users) {
		return nil, errors.New("wrong dispatch input")
	}
	return r.items, r.dispatchErr
}

type publisher struct {
	items []*models.Notification
	err   error
}

func (p *publisher) Publish(_ context.Context, n *models.Notification) error {
	p.items = append(p.items, n)
	return p.err
}

func TestConsumeDelivery(t *testing.T) {
	t.Parallel()
	failure := errors.New("database unavailable")
	for _, tt := range []struct {
		name, eventType                              string
		resolveErr, dispatchErr, publishErr, wantErr error
		resolve, dispatch, live                      bool
		count                                        int
	}{
		{name: "internal event ignored", eventType: "sla.CREATED"},
		{name: "recipient failure", eventType: "ticket.created", resolveErr: failure, wantErr: failure, resolve: true},
		{name: "dispatch failure", eventType: "ticket.created", dispatchErr: failure, wantErr: failure, resolve: true, dispatch: true},
		{name: "publish all new notifications", eventType: "ticket.created", resolve: true, dispatch: true, live: true, count: 2},
		{name: "publish failure does not stop other recipients", eventType: "ticket.created", publishErr: failure, resolve: true, dispatch: true, live: true, count: 2},
		{name: "live channel disabled", eventType: "ticket.completed", resolve: true, dispatch: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := models.Event{ID: "event-1", Type: tt.eventType, Payload: map[string]any{"ticket_id": "123"}}
			r := &dispatchStore{event: e, users: []uuid.UUID{uuid.New(), uuid.New()}, items: []*models.Notification{{ID: uuid.New()}, {ID: uuid.New()}}, resolveErr: tt.resolveErr, dispatchErr: tt.dispatchErr}
			p := &publisher{err: tt.publishErr}
			var live Publisher
			if tt.live {
				live = p
			}
			err := New(r, live).Consume(context.Background(), e)
			if !errors.Is(err, tt.wantErr) || r.resolved != tt.resolve || r.dispatched != tt.dispatch || len(p.items) != tt.count {
				t.Fatalf("Consume(%q) = %v, resolved=%v dispatched=%v published=%d; want %v %v %v %d", tt.eventType, err, r.resolved, r.dispatched, len(p.items), tt.wantErr, tt.resolve, tt.dispatch, tt.count)
			}
			if tt.count > 0 && !reflect.DeepEqual(p.items, r.items) {
				t.Fatalf("published = %v, want %v", p.items, r.items)
			}
		})
	}
}

type deviceStore struct {
	store
	got *models.Device
	err error
}

func (r *deviceStore) RegisterDevice(_ context.Context, v *models.Device) (*models.Device, error) {
	r.got = v
	return v, r.err
}
func TestRegisterDevice(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, platform, token, wantPlatform string
		valid                               bool
	}{
		{"android normalized", " Android ", "token", "android", true},
		{"ios", "ios", "token", "ios", true},
		{"web", "web", "token", "web", true},
		{"missing token", "web", "", "web", false},
		{"unsupported platform", "desktop", "token", "desktop", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &deviceStore{}
			v := &models.Device{UserID: uuid.New(), Token: tt.token, Platform: tt.platform}
			got, err := New(r, nil).RegisterDevice(context.Background(), v)
			if v.Platform != tt.wantPlatform || (err == nil) != tt.valid || (r.got != nil) != tt.valid || (tt.valid && got != v) {
				t.Fatalf("RegisterDevice(%q) = %v, %v, stored=%v; want platform=%q valid=%v", tt.platform, got, err, r.got, tt.wantPlatform, tt.valid)
			}
		})
	}
}

type templateRecorder struct {
	store
	got *models.Template
	err error
}

func (r *templateRecorder) UpsertTemplate(_ context.Context, v *models.Template) (*models.Template, error) {
	r.got = v
	return v, r.err
}
func TestUpsertTemplateValidation(t *testing.T) {
	t.Parallel()
	for _, v := range []models.Template{{}, {EventType: "ticket.created", Channel: "IN_APP"}, {Body: "body", Channel: "IN_APP"}, {EventType: "ticket.created", Body: "body"}} {
		r := &templateRecorder{}
		if _, err := New(r, nil).UpsertTemplate(context.Background(), &v); err == nil || r.got != nil {
			t.Fatalf("UpsertTemplate(%+v) = %v, stored=%v; want rejection without write", v, err, r.got)
		}
	}
	v := &models.Template{EventType: "ticket.created", Channel: "IN_APP", Body: "body"}
	for _, wantErr := range []error{nil, context.Canceled} {
		r := &templateRecorder{err: wantErr}
		got, err := New(r, nil).UpsertTemplate(context.Background(), v)
		if got != v || r.got != v || !errors.Is(err, wantErr) {
			t.Fatalf("UpsertTemplate(valid) = %v, %v; want input, %v", got, err, wantErr)
		}
	}
}
func TestMapErr(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		input, want error
	}{
		{"success", nil, nil}, {"no rows", pgx.ErrNoRows, ErrNotFound}, {"other", context.Canceled, context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapErr(tt.input); !errors.Is(got, tt.want) {
				t.Errorf("mapErr(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
