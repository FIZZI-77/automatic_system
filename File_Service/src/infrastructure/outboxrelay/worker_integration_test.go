//go:build integration

package outboxrelay

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type recordingWriter struct {
	messages []kafka.Message
	err      error
}

func (w *recordingWriter) WriteMessages(_ context.Context, messages ...kafka.Message) error {
	w.messages = append(w.messages, messages...)
	return w.err
}

func TestRelayRetriesStableEventAfterRestart(t *testing.T) {
	db := outboxPool(t)
	aggregate := uuid.NewString()
	if _, err := db.Exec(t.Context(), `INSERT INTO outbox_events(aggregate_id,event_type,payload) VALUES($1,'example.created','{"status":"UPLOADED"}')`, aggregate); err != nil {
		t.Fatal(err)
	}
	unavailable := errors.New("Kafka unavailable")
	writer := &recordingWriter{err: unavailable}
	if err := New(db, writer, zap.NewNop()).publishNext(t.Context()); !errors.Is(err, unavailable) {
		t.Fatalf("publishNext(unavailable Kafka) = %v, want %v", err, unavailable)
	}
	var pending bool
	var attempts int
	if err := db.QueryRow(t.Context(), `SELECT sent_at IS NULL,attempts FROM outbox_events`).Scan(&pending, &attempts); err != nil || !pending || attempts != 1 {
		t.Fatalf("failed publish state = (pending %v, attempts %d, %v), want (true,1,nil)", pending, attempts, err)
	}
	if _, err := db.Exec(t.Context(), `UPDATE outbox_events SET next_attempt_at=now()`); err != nil {
		t.Fatal(err)
	}
	writer.err = nil
	restarted := New(db, writer, zap.NewNop())
	if err := restarted.publishNext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(writer.messages) != 2 || !reflect.DeepEqual(writer.messages[0], writer.messages[1]) {
		t.Fatalf("retry messages = %v, want identical key, payload, headers and original timestamp", writer.messages)
	}
	var payload map[string]any
	if err := json.Unmarshal(writer.messages[1].Value, &payload); err != nil {
		t.Fatal(err)
	}
	eventID, _ := payload["event_id"].(string)
	if _, err := uuid.Parse(eventID); err != nil {
		t.Errorf("published event_id = %q, want UUID: %v", eventID, err)
	}
	if eventID == "" || payload["event_version"] != float64(1) || payload["event_type"] != "example.created" || string(writer.messages[1].Key) != aggregate {
		t.Errorf("published event = %v, key %s, want stable versioned event for %s", payload, writer.messages[1].Key, aggregate)
	}
	if err := restarted.publishNext(t.Context()); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("publishNext(acknowledged event) = %v, want no rows", err)
	}
}

func TestRelayRetriesAfterKafkaAckAndDatabaseFailure(t *testing.T) {
	db := outboxPool(t)
	_, err := db.Exec(t.Context(), `INSERT INTO outbox_events(aggregate_id,event_type,payload) VALUES(gen_random_uuid(),'example.created','{}');
        CREATE FUNCTION reject_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected ack failure'; END $$;
        CREATE TRIGGER reject_ack BEFORE UPDATE ON outbox_events FOR EACH ROW EXECUTE FUNCTION reject_ack()`)
	if err != nil {
		t.Fatal(err)
	}
	writer := &recordingWriter{}
	worker := New(db, writer, zap.NewNop())
	if err := worker.publishNext(t.Context()); err == nil {
		t.Fatal("publishNext(database ack failure) succeeded, want error")
	}
	if _, err := db.Exec(t.Context(), `DROP TRIGGER reject_ack ON outbox_events`); err != nil {
		t.Fatal(err)
	}
	if err := worker.publishNext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(writer.messages) != 2 || !reflect.DeepEqual(writer.messages[0], writer.messages[1]) {
		t.Fatalf("messages after ambiguous acknowledgment = %v, want identical event for consumer deduplication", writer.messages)
	}
}

func outboxPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("OUTBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set OUTBOX_TEST_DATABASE_URL to run isolated PostgreSQL outbox tests")
	}
	base, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "outbox_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := base.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		base.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := base.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		base.Close()
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	db, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	paths, err := filepath.Glob("../../../scheme/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("migration paths = %v, %v, want SQL migrations", paths, err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		up := strings.Split(string(data), "-- +goose Down")[0]
		if _, err := db.Exec(t.Context(), up); err != nil {
			t.Fatalf("apply %s: %v", path, err)
		}
	}
	return db
}
