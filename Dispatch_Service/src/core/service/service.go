package service

import (
	"context"
	"errors"
	"time"

	"dispatch/src/core/repository"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"go.uber.org/zap"
)

type Dependencies struct {
	Tickets  ticketv1.TicketServiceClient
	Brigades brigadev1.BrigadeServiceClient
	Location locationv1.LocationServiceClient
	Routing  routingv1.RoutingServiceClient
}

type Service struct {
	repo *repository.Repository
	deps Dependencies
	ttl  time.Duration
	log  *zap.Logger
}

func New(repo *repository.Repository, deps Dependencies, ttl time.Duration, logger *zap.Logger) (*Service, error) {
	if repo == nil || deps.Tickets == nil || deps.Brigades == nil || deps.Location == nil || deps.Routing == nil {
		return nil, errors.New("dispatch: all dependencies are required")
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{repo: repo, deps: deps, ttl: ttl, log: logger}, nil
}

func (s *Service) Cleanup(ctx context.Context) error {
	const batchSize = 100
	for {
		items, err := s.repo.Expire(ctx, batchSize)
		if err != nil {
			return err
		}
		for _, item := range items {
			if item.BrigadeID != nil {
				s.release(forwardMetadata(ctx), *item.BrigadeID, item.RequestedBy)
			}
		}
		if len(items) < batchSize {
			return nil
		}
	}
}
