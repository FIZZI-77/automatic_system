package tickethistory

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

func TestIncidentFromMessageUsesParentOnLink(t *testing.T) {
	assetID, categoryID := uuid.New(), uuid.New()
	requestID, incidentID := uuid.New(), uuid.New()
	linkedAt := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	for _, kind := range []string{"ticket.updated", "ticket.completed", "ticket.request_attached"} {
		t.Run(kind, func(t *testing.T) {
			msg := kafka.Message{
				Headers: []kafka.Header{{Key: "event_type", Value: []byte(kind)}},
				Value: []byte(fmt.Sprintf(`{
					"id":%q,"incident_id":%q,"asset_id":%q,"category_id":%q,
					"priority":"HIGH","title":"Lamp broken","updated_at":%q
				}`, requestID, incidentID, assetID, categoryID, linkedAt.Format(time.RFC3339))),
			}
			incident, err := incidentFromMessage(msg)
			if err != nil || incident == nil {
				t.Fatalf("incidentFromMessage(%s) = %+v, %v", kind, incident, err)
			}
			if incident.TicketID == nil || *incident.TicketID != incidentID || incident.AssetID != assetID ||
				incident.FailureType != categoryID.String() || !incident.OccurredAt.Equal(linkedAt) {
				t.Fatalf("incidentFromMessage(%s) = %+v; want parent %s, asset %s at %s", kind, incident, incidentID, assetID, linkedAt)
			}
		})
	}
}

func TestIncidentFromMessageIgnoresUnlinkedTicket(t *testing.T) {
	msg := kafka.Message{
		Headers: []kafka.Header{{Key: "event_type", Value: []byte("ticket.created")}},
		Value:   []byte(`{"ticket_id":"3be6fb97-2c9e-4da8-a8c6-62ea634ec271","asset_id":null}`),
	}
	incident, err := incidentFromMessage(msg)
	if err != nil || incident != nil {
		t.Fatalf("incidentFromMessage(unlinked) = %+v, %v; want nil, nil", incident, err)
	}
}
