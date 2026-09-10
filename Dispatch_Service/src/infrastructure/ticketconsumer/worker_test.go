package ticketconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"dispatch/models"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

type fakeDispatcher struct {
	input *models.AutoInput
	err   error
}

func (f *fakeDispatcher) AutoDispatch(_ context.Context, input *models.AutoInput) (*models.Operation, error) {
	f.input = input
	return &models.Operation{}, f.err
}

func TestApplyStartsEmergencyAutoDispatch(t *testing.T) {
	t.Parallel()
	eventID := uuid.New()
	ticketID := uuid.New()
	actorID := uuid.New()
	payload, err := json.Marshal(ticketCreated{EventID: eventID.String(), EventType: "ticket.created", TicketID: ticketID.String(), Priority: "EMERGENCY"})
	if err != nil {
		t.Fatalf("json.Marshal(ticketCreated) error = %v", err)
	}
	dispatcher := new(fakeDispatcher)
	worker := &Worker{dispatch: dispatcher, config: Config{ActorID: actorID, CandidateLimit: 12}}
	if err = worker.apply(context.Background(), kafka.Message{Value: payload}); err != nil {
		t.Fatalf("Worker.apply(emergency) error = %v", err)
	}
	if dispatcher.input == nil || dispatcher.input.TicketID != ticketID || dispatcher.input.RequestedBy != actorID || dispatcher.input.CandidateLimit != 12 || dispatcher.input.TriggerEventID == nil || *dispatcher.input.TriggerEventID != eventID {
		t.Errorf("Worker.apply(emergency) AutoInput = %+v, want ticket %s actor %s event %s", dispatcher.input, ticketID, actorID, eventID)
	}
}

func TestApplyIgnoresNonEmergencyEvents(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event_id":"` + uuid.NewString() + `","event_type":"ticket.created","ticket_id":"` + uuid.NewString() + `","priority":"HIGH"}`)
	dispatcher := new(fakeDispatcher)
	worker := &Worker{dispatch: dispatcher, config: Config{ActorID: uuid.New()}}
	if err := worker.apply(context.Background(), kafka.Message{Value: payload}); err != nil {
		t.Fatalf("Worker.apply(high priority) error = %v", err)
	}
	if dispatcher.input != nil {
		t.Errorf("Worker.apply(high priority) AutoInput = %+v, want no call", dispatcher.input)
	}
}

func TestApplyReturnsDispatchError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("dispatch unavailable")
	payload := []byte(`{"event_id":"` + uuid.NewString() + `","event_type":"ticket.created","ticket_id":"` + uuid.NewString() + `","priority":"EMERGENCY"}`)
	worker := &Worker{dispatch: &fakeDispatcher{err: wantErr}, config: Config{ActorID: uuid.New()}}
	if err := worker.apply(context.Background(), kafka.Message{Value: payload}); !errors.Is(err, wantErr) {
		t.Errorf("Worker.apply(emergency) error = %v, want %v", err, wantErr)
	}
}

func TestRetryHeadersReplaceAttemptAndBoundError(t *testing.T) {
	t.Parallel()
	headers := retryHeaders([]kafka.Header{{Key: retryHeader, Value: []byte("1")}, {Key: "event_type", Value: []byte("ticket.created")}}, 2, errors.New("failed"))
	if got := retries(headers); got != 2 {
		t.Errorf("retries(retryHeaders) = %d, want 2", got)
	}
	if got := header(headers, "event_type"); got != "ticket.created" {
		t.Errorf("header(event_type) = %q, want ticket.created", got)
	}
	if got := header(headers, "x-error"); got != "failed" {
		t.Errorf("header(x-error) = %q, want failed", got)
	}
}
