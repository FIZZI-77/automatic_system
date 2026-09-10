package main

import (
	"context"
	"os"
	"strconv"
	"sync"

	"dispatch/src/core/service"
	"dispatch/src/infrastructure/ticketconsumer"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func startTicketConsumer(ctx context.Context, value *service.Service, workers *sync.WaitGroup, logger *zap.Logger) *ticketconsumer.Worker {
	brokers := split(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		logger.Warn("dispatch ticket consumer disabled: KAFKA_BROKERS is empty")
		return nil
	}
	actorID, err := uuid.Parse(os.Getenv("AUTO_DISPATCH_ACTOR_ID"))
	if err != nil {
		logger.Fatal("AUTO_DISPATCH_ACTOR_ID must be a UUID", zap.Error(err))
	}
	worker, err := ticketconsumer.New(value, ticketconsumer.Config{
		Brokers: brokers, Topic: env("KAFKA_TICKET_TOPIC", "tickets.events.v1"),
		GroupID: env("KAFKA_TICKET_GROUP", "dispatch-emergency-v1"), ActorID: actorID,
		CandidateLimit: int32(integer("AUTO_DISPATCH_CANDIDATE_LIMIT", 10)), MaxAttempts: integer("KAFKA_TICKET_MAX_ATTEMPTS", 5),
	}, logger)
	if err != nil {
		logger.Fatal("create dispatch ticket consumer", zap.Error(err))
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if runErr := worker.Run(ctx); runErr != nil {
			logger.Error("dispatch ticket consumer stopped", zap.Error(runErr))
		}
	}()
	return worker
}

func integer(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
