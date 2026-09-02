package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"routing/models"
	"routing/src/core/repository"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestRouteRepositoryPersistsRouteAndOutbox(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()
	container, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("routing_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	defer container.Terminate(ctx)

	connectionString, err := container.ConnectionString(
		ctx,
		"sslmode=disable",
	)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	migrationDB, err := sql.Open("pgx", connectionString)
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	defer migrationDB.Close()
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set dialect: %v", err)
	}
	if err = goose.Up(
		migrationDB,
		filepath.Clean("../../scheme"),
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	repo := repository.NewRouteRepo(pool, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	success := true
	durationMS := 125.5
	route := &models.Route{
		ID:          uuid.NewString(),
		TicketID:    uuid.NewString(),
		BrigadeID:   uuid.NewString(),
		Status:      models.RouteStatusPlanned,
		Origin:      models.Point{Latitude: 55.75, Longitude: 37.61},
		Destination: models.Point{Latitude: 55.76, Longitude: 37.62},
		Options:     models.RouteOptions{TravelMode: models.TravelModeAuto},
		Calculation: models.CalculatedRoute{
			Engine: "valhalla",
			Summary: models.RouteSummary{
				DistanceMeters:  1500,
				DurationSeconds: 120,
			},
		},
		Revision:                  1,
		CreatedAt:                 now,
		UpdatedAt:                 now,
		CalculationStartedAt:      &now,
		CalculationFinishedAt:     &now,
		CalculationDurationMillis: &durationMS,
		CalculationSuccess:        &success,
	}
	created, err := repo.CreateRoute(ctx, route)
	if err != nil {
		t.Fatalf("create route: %v", err)
	}
	loaded, err := repo.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("get route: %v", err)
	}
	if loaded.Calculation.Engine != "valhalla" ||
		loaded.Calculation.Summary.DistanceMeters != 1500 {
		t.Fatalf("loaded route = %#v", loaded)
	}

	var eventID, payloadEventID, eventType string
	var payloadBytes []byte
	if err = pool.QueryRow(
		ctx,
		"SELECT id::text,event_type,payload FROM outbox_events WHERE aggregate_id = $1",
		route.ID,
	).Scan(&eventID, &eventType, &payloadBytes); err != nil {
		t.Fatalf("read outbox event: %v", err)
	}
	if eventType != "routing.route.created.v1" {
		t.Fatalf("event type = %s", eventType)
	}
	var payload map[string]any
	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	payloadEventID, _ = payload["event_id"].(string)
	if payloadEventID != eventID || payload["engine"] != "valhalla" || payload["travel_mode"] != "auto" || payload["success"] != true {
		t.Fatalf("routing event envelope = %#v, want event id and normalized calculation fields", payload)
	}

	failureFinishedAt := now.Add(250 * time.Millisecond)
	if err = repo.RecordCalculationFailure(ctx, models.CalculationFailure{
		AggregateType:         "ticket",
		AggregateID:           route.TicketID,
		TicketID:              route.TicketID,
		BrigadeID:             route.BrigadeID,
		Engine:                "valhalla",
		TravelMode:            models.TravelModeAuto,
		FailureCode:           "ENGINE_TIMEOUT",
		FailureReason:         "deadline exceeded",
		CalculationStartedAt:  now,
		CalculationFinishedAt: failureFinishedAt,
		CalculationDurationMS: 250,
	}); err != nil {
		t.Fatalf("RecordCalculationFailure() error = %v", err)
	}
	var failureAggregateType string
	if err = pool.QueryRow(
		ctx,
		`SELECT aggregate_type,payload FROM outbox_events WHERE aggregate_id=$1 AND event_type='routing.calculation.failed.v1'`,
		route.TicketID,
	).Scan(&failureAggregateType, &payloadBytes); err != nil {
		t.Fatalf("read calculation failure event: %v", err)
	}
	payload = nil
	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode calculation failure event: %v", err)
	}
	if failureAggregateType != "ticket" || payload["success"] != false || payload["failure_code"] != "ENGINE_TIMEOUT" || payload["route_id"] != nil {
		t.Errorf("calculation failure event = aggregate %q payload %#v, want ticket aggregate without fictitious route", failureAggregateType, payload)
	}
}
