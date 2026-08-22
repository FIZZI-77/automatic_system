package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	appconfig "transponder-simulator/internal/appconfig"
	"transponder-simulator/internal/simulator"
)

func main() {
	if err := appconfig.Load(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	cfg, err := simulator.LoadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	route, err := simulator.LoadRoute(cfg.RouteFile)
	if err != nil {
		log.Fatalf("route error: %v", err)
	}

	sender := simulator.NewSender(cfg)
	runner := simulator.NewRunner(cfg, route, sender, log.Default())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err = runner.Run(ctx); err != nil {
		log.Fatalf("simulator stopped: %v", err)
	}
}
