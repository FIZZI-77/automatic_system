package service

import (
	"context"
	"errors"
	"time"

	"dispatch/models"
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
	items, err := s.repo.Expire(ctx, batchSize)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err = s.cleanupExpired(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) cleanupExpired(ctx context.Context, item *models.Operation) (err error) {
	releaseLock, acquired, err := s.repo.TryOperationLock(ctx, item.ID)
	if err != nil || !acquired {
		return err
	}
	defer func() { err = errors.Join(err, releaseLock()) }()
	item, err = s.repo.Get(ctx, item.ID)
	if errors.Is(err, models.ErrNotFound) {
		return nil
	}
	if err != nil || time.Now().UTC().Before(item.ExpiresAt) {
		return err
	}
	compensationCtx := compensationContext(ctx, item)
	switch item.Status {
	case models.StatusConfirming:
		_, err = s.finishConfirm(compensationCtx, item, item.RequestedBy)
		if err != nil {
			s.log.Error("recover confirming dispatch", zap.Error(err), zap.String("operation_id", item.ID.String()))
			return nil
		}
	case models.StatusReserved:
		if item.BrigadeID == nil {
			return nil
		}
		if err = s.release(compensationCtx, *item.BrigadeID, item.RequestedBy); err != nil {
			return nil
		}
		_, err = s.repo.SetTerminal(ctx, item.ID, models.StatusExpired, "dispatch operation expired", item.Version)
	case models.StatusPending:
		_, err = s.repo.SetTerminal(ctx, item.ID, models.StatusExpired, "dispatch operation expired", item.Version)
	}
	if errors.Is(err, models.ErrConflict) {
		return nil
	}
	return err
}
