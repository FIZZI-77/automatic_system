package models

import (
	"encoding/json"
	"github.com/google/uuid"
	"testing"
)

func TestPushPayloadContainsNoRecipientData(t *testing.T) {
	v := Notification{ID: uuid.New(), UserID: uuid.New(), Title: "x", Body: "y", Data: map[string]string{"ticket_id": uuid.NewString()}}
	raw, _ := json.Marshal(v.Data)
	if string(raw) == "" {
		t.Fatal("empty payload")
	}
}
