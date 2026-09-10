package delivery

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"notification/src/core/repository"
	"notification/src/infrastructure/sender"
	"time"
)

type Worker struct {
	repo    *repository.Repository
	senders map[string]sender.Sender
	log     *zap.Logger
}

func New(r *repository.Repository, s map[string]sender.Sender, l *zap.Logger) *Worker {
	return &Worker{repo: r, senders: s, log: l}
}
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for {
			d, n, e := w.repo.ClaimDelivery(ctx)
			if errors.Is(e, pgx.ErrNoRows) {
				break
			}
			if e != nil {
				return e
			}
			s := w.senders[d.Channel]
			if s == nil {
				s = sender.Disabled{Channel: d.Channel}
			}
			provider, e := s.Send(ctx, d, n)
			if e == nil {
				e = w.repo.DeliverySent(ctx, d.ID, provider)
			} else {
				if errors.Is(e, sender.ErrPermanent) && d.Channel == "PUSH" {
					_ = w.repo.DeactivateToken(ctx, d.Recipient)
					d.Attempts = 8
				}
				e = w.repo.DeliveryFailed(ctx, d, e.Error())
			}
			if e != nil {
				w.log.Error("delivery update failed", zap.Error(e))
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
