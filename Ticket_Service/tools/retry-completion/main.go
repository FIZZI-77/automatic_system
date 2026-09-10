package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"ticket/pkg"
	appconfig "ticket/pkg/config"
	"ticket/src/infrastructure/completionsaga"
)

func main() {
	reportIDValue := flag.String("report-id", "", "work report UUID")
	timeout := flag.Duration("timeout", 10*time.Minute, "timeout for the resumed generation attempt")
	flag.Parse()

	if err := appconfig.Load(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	reportID, err := uuid.Parse(*reportIDValue)
	if err != nil {
		log.Fatalf("invalid -report-id: %v", err)
	}
	db, err := pkg.NewPostgresDB(pkg.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DbName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("SSLMODE"),
	})
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = completionsaga.Resume(ctx, db, reportID, *timeout); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("completion saga %s resumed\n", reportID)
}
