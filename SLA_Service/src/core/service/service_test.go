package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"sla/models"

	"github.com/google/uuid"
)

type eventStore struct {
	store
	rule               *models.Rule
	matchErr, applyErr error
	matched, applied   bool
	event              models.TicketEvent
}

func (r *eventStore) MatchRule(_ context.Context, d, c uuid.UUID, p models.Priority) (*models.Rule, error) {
	r.matched = true
	if d != r.event.DepartmentID || c != r.event.CategoryID || p != r.event.Priority {
		return nil, errors.New("incorrect match criteria")
	}
	return r.rule, r.matchErr
}

func (r *eventStore) ApplyEvent(_ context.Context, e models.TicketEvent, rule *models.Rule) error {
	r.applied = true
	if !reflect.DeepEqual(e, r.event) || rule != r.rule {
		return errors.New("incorrect event or rule")
	}
	return r.applyErr
}

func TestConsume(t *testing.T) {
	t.Parallel()
	failure := errors.New("storage unavailable")
	for _, tt := range []struct {
		name                        string
		event                       models.TicketEvent
		matchErr, applyErr, wantErr error
		match, apply                bool
	}{
		{name: "missing event ID", event: models.TicketEvent{TicketID: uuid.New()}, wantErr: models.ErrInvalidArgument},
		{name: "missing ticket ID", event: models.TicketEvent{EventID: "e"}, wantErr: models.ErrInvalidArgument},
		{name: "partial event skips matching", event: models.TicketEvent{EventID: "e", TicketID: uuid.New()}, apply: true},
		{name: "full event matches rule", event: fullEvent(), match: true, apply: true},
		{name: "match error stops processing", event: fullEvent(), matchErr: failure, wantErr: failure, match: true},
		{name: "no matching rule", event: fullEvent(), matchErr: models.ErrNotFound, wantErr: models.ErrNotFound, match: true},
		{name: "apply error propagates", event: fullEvent(), applyErr: failure, wantErr: failure, match: true, apply: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &eventStore{event: tt.event, matchErr: tt.matchErr, applyErr: tt.applyErr}
			if tt.match {
				r.rule = &models.Rule{ID: uuid.New()}
			}
			err := New(r).Consume(context.Background(), tt.event)
			if !errors.Is(err, tt.wantErr) || r.matched != tt.match || r.applied != tt.apply {
				t.Fatalf("Consume(%+v) = %v, matched=%v applied=%v; want %v, %v, %v", tt.event, err, r.matched, r.applied, tt.wantErr, tt.match, tt.apply)
			}
		})
	}
}

func fullEvent() models.TicketEvent {
	return models.TicketEvent{EventID: "event-1", TicketID: uuid.New(), DepartmentID: uuid.New(), CategoryID: uuid.New(), Priority: models.PriorityHigh}
}

type ruleRecorder struct {
	store
	got *models.Rule
	err error
}

func (r *ruleRecorder) CreateRule(_ context.Context, v *models.Rule) (*models.Rule, error) {
	r.got = v
	return v, r.err
}
func (r *ruleRecorder) UpdateRule(_ context.Context, v *models.Rule) (*models.Rule, error) {
	r.got = v
	return v, r.err
}

func TestRuleValidation(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"create", "update"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			r := &ruleRecorder{}
			s := New(r)
			call := s.CreateRule
			if operation == "update" {
				call = s.UpdateRule
			}
			if _, err := call(context.Background(), &models.Rule{}); !errors.Is(err, models.ErrInvalidArgument) || r.got != nil {
				t.Fatalf("%s(invalid rule) = %v, stored=%v; want invalid argument without write", operation, err, r.got)
			}
			v := &models.Rule{Name: "urgent", ResponseTime: time.Minute, ResolutionTime: time.Hour, WarningPercent: 80}
			for _, storageErr := range []error{nil, context.Canceled} {
				r.err = storageErr
				got, err := call(context.Background(), v)
				if got != v || r.got != v || !errors.Is(err, storageErr) {
					t.Fatalf("%s(valid rule) = %v, %v; want input and %v", operation, got, err, storageErr)
				}
			}
		})
	}
}
