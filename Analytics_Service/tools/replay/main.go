package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

var versionPattern = regexp.MustCompile(`^v[1-9][0-9]*$`)

type counts struct {
	Events, Eligible, Unknown uint64
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(parent context.Context, args []string) error {
	if len(args) != 1 || !versionPattern.MatchString(args[0]) {
		return errors.New("usage: replay v<positive-version>")
	}
	address := strings.TrimSpace(os.Getenv("CLICKHOUSE_ADDR"))
	if address == "" {
		return errors.New("CLICKHOUSE_ADDR is required")
	}
	database := env("CLICKHOUSE_DATABASE", "analytics")
	db, err := clickhouse.Open(&clickhouse.Options{
		Addr: strings.Split(address, ","),
		Auth: clickhouse.Auth{Database: database, Username: env("CLICKHOUSE_USER", "default"), Password: os.Getenv("CLICKHOUSE_PASSWORD")},
	})
	if err != nil {
		return fmt.Errorf("open ClickHouse: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	return replay(ctx, db, database, args[0])
}

func replay(ctx context.Context, db driver.Conn, database, version string) error {
	if !versionPattern.MatchString(version) || !identifierPattern.MatchString(database) {
		return errors.New("invalid replay identifier")
	}
	source := database + ".domain_events"
	current := database + ".domain_events_projection_v1"
	target := database + ".domain_events_replay_" + version
	if err := db.Exec(ctx, "DROP TABLE IF EXISTS "+target); err != nil {
		return fmt.Errorf("drop stale replay table: %w", err)
	}
	if err := db.Exec(ctx, "CREATE TABLE "+target+" AS "+current); err != nil {
		return fmt.Errorf("create replay table: %w", err)
	}
	if err := db.Exec(ctx, "INSERT INTO "+target+" SELECT * FROM "+source); err != nil {
		return fmt.Errorf("populate replay table: %w", err)
	}
	if err := db.Exec(ctx, "OPTIMIZE TABLE "+target+" FINAL"); err != nil {
		return fmt.Errorf("deduplicate replay table: %w", err)
	}
	sourceCounts, err := tableCounts(ctx, db, source)
	if err != nil {
		return fmt.Errorf("count source: %w", err)
	}
	targetCounts, err := tableCounts(ctx, db, target)
	if err != nil {
		return fmt.Errorf("count replay: %w", err)
	}
	if err = reconcileCounts("replay", sourceCounts, targetCounts); err != nil {
		return err
	}
	view := database + ".domain_events_projection_v1_mv"
	createView := "CREATE MATERIALIZED VIEW " + view + " TO " + current + " AS SELECT * FROM " + source
	if err = db.Exec(ctx, "DROP VIEW IF EXISTS "+view); err != nil {
		return fmt.Errorf("pause projection materialized view: %w", err)
	}
	if err = db.Exec(ctx, "EXCHANGE TABLES "+current+" AND "+target); err != nil {
		_ = db.Exec(ctx, createView)
		return fmt.Errorf("atomically switch replay table: %w", err)
	}
	if err = db.Exec(ctx, createView); err != nil {
		rollbackErr := db.Exec(ctx, "EXCHANGE TABLES "+current+" AND "+target)
		restoreErr := db.Exec(ctx, createView)
		return errors.Join(
			fmt.Errorf("restore projection materialized view: %w", err),
			wrapOptional("rollback replay table switch", rollbackErr),
			wrapOptional("restore original projection view", restoreErr),
		)
	}
	// Reinsert the raw source after restoring the view to cover events accepted
	// during the short view replacement window. ReplacingMergeTree deduplicates
	// them by (topic,event_id,version).
	if err = db.Exec(ctx, "INSERT INTO "+current+" SELECT * FROM "+source); err != nil {
		return fmt.Errorf("catch up replay projection: %w", err)
	}
	if err = db.Exec(ctx, "OPTIMIZE TABLE "+current+" FINAL"); err != nil {
		return fmt.Errorf("deduplicate switched projection: %w", err)
	}
	finalSourceCounts, err := tableCounts(ctx, db, source)
	if err != nil {
		return fmt.Errorf("recount source after switch: %w", err)
	}
	finalCounts, err := tableCounts(ctx, db, current)
	if err != nil {
		return fmt.Errorf("count switched projection: %w", err)
	}
	return reconcileCounts("post-switch", finalSourceCounts, finalCounts)
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func tableCounts(ctx context.Context, db driver.Conn, table string) (counts, error) {
	var result counts
	err := db.QueryRow(ctx, "SELECT uniqExact(topic,event_id),countIf(projection_eligible),countIf(NOT projection_eligible) FROM "+table+" FINAL").Scan(
		&result.Events, &result.Eligible, &result.Unknown,
	)
	return result, err
}

func reconcileCounts(stage string, source, projection counts) error {
	if source == projection {
		return nil
	}
	return fmt.Errorf("%s reconciliation failed: source=%+v projection=%+v", stage, source, projection)
}

func wrapOptional(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
