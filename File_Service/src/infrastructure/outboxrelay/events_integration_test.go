//go:build integration

package outboxrelay

import (
	"testing"

	"file/models"
	"file/src/core/repository"
	"github.com/google/uuid"
)

func TestFileTransitionsEnqueueAtomically(t *testing.T) {
	db := outboxPool(t)
	repo := repository.New(db, db)
	file, err := repo.Create(t.Context(), models.CreateInput{
		OwnerUserID: uuid.New(), Name: "private-name.csv", ContentType: "text/csv", Size: 4,
	}, "private-object-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Confirm(t.Context(), file.ID); err != nil {
		t.Fatal(err)
	}
	link := models.LinkInput{ResourceType: "ticket", ResourceID: uuid.New()}
	if _, err := repo.Link(t.Context(), file.ID, link); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Link(t.Context(), file.ID, link); err != nil {
		t.Fatal(err)
	}
	link.ResourceID = uuid.New()
	if _, err := repo.Link(t.Context(), file.ID, link); err != nil {
		t.Fatal(err)
	}
	if err := repo.QueueDeletion(t.Context(), file.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.QueueDeletion(t.Context(), file.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	var sensitive bool
	if err := db.QueryRow(t.Context(), `SELECT count(*),bool_or(payload ?| ARRAY['object_key','name','checksum','url']) FROM outbox_events`).Scan(&count, &sensitive); err != nil || count != 5 || sensitive {
		t.Fatalf("file transition events = (count %d, sensitive %v, %v), want five events without private storage data", count, sensitive, err)
	}
	var deleted int
	if err := db.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events WHERE event_type='file.deleted' AND payload->>'status'='DELETED'`).Scan(&deleted); err != nil || deleted != 1 {
		t.Errorf("repeated deletion events = %d, %v, want one", deleted, err)
	}
	// Failure to persist an event must also reject the metadata mutation.
	_, err = db.Exec(t.Context(), `CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'outbox unavailable'; END $$;
        CREATE TRIGGER reject_event BEFORE INSERT ON outbox_events FOR EACH ROW EXECUTE FUNCTION reject_event()`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.Create(t.Context(), models.CreateInput{OwnerUserID: uuid.New(), Name: "fail.csv", ContentType: "text/csv", Size: 4}, "failed-key")
	if err == nil {
		t.Fatal("Create(outbox failure) succeeded, want rollback")
	}
	if err := db.QueryRow(t.Context(), `SELECT count(*) FROM files WHERE object_key='failed-key'`).Scan(&count); err != nil || count != 0 {
		t.Errorf("metadata after outbox failure = %d, %v, want no file", count, err)
	}
}
