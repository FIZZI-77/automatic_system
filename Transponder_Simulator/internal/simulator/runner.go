package simulator

import (
	"context"
	"fmt"
	"log"
	"time"
)

type Runner struct {
	cfg    Config
	route  Route
	sender Sender
	logger *log.Logger
}

func NewRunner(cfg Config, route Route, sender Sender, logger *log.Logger) *Runner {
	return &Runner{cfg: cfg, route: route, sender: sender, logger: logger}
}

func (r *Runner) Run(ctx context.Context) error {
	r.logger.Printf("transponder simulator started: %s route=%q points=%d", r.cfg.String(), r.route.Name, len(r.route.Points))
	var sequence uint64
	for {
		for index, point := range r.route.Points {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			next := r.route.Points[(index+1)%len(r.route.Points)]
			sequence++
			event := NewEvent(r.cfg, point, next, sequence, now())
			if err := r.sender.Send(ctx, event); err != nil {
				return fmt.Errorf("point %d sequence %d: %w", index, sequence, err)
			}
			r.logger.Printf("position sent: sequence=%d latitude=%.6f longitude=%.6f speed=%.1f heading=%.1f",
				sequence, point.Latitude, point.Longitude, event.Payload.SpeedKMH, event.Payload.Heading)
			if err := wait(ctx, r.cfg.Interval); err != nil {
				return nil
			}
		}
		if !r.cfg.LoopRoute {
			return nil
		}
	}
}

var now = func() time.Time { return time.Now() }

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
