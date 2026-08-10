package positionhistory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"location/models"
	"location/src/core/service"

	"go.uber.org/zap"
)

type repositoryStub struct {
	mu      sync.Mutex
	batches [][]*models.Position
	err     error
}

func (r *repositoryStub) AppendPositionsBatch(
	_ context.Context,
	positions []*models.Position,
) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, append([]*models.Position(nil), positions...))
	if r.err != nil {
		return 0, r.err
	}
	return int64(len(positions)), nil
}

func TestWorkerFlushesWhenBatchSizeReached(t *testing.T) {
	repo := &repositoryStub{}
	worker, err := New(
		service.NewMemoryPositionBuffer(10),
		repo,
		Config{BatchSize: 2, FlushInterval: time.Hour},
		zap.NewNop(),
	)
	if err != nil {
		t.Fatalf("new worker: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = worker.Run(ctx) }()

	_ = worker.Add(&models.Position{Sequence: 1})
	_ = worker.Add(&models.Position{Sequence: 2})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		repo.mu.Lock()
		count := len(repo.batches)
		repo.mu.Unlock()
		if count == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.batches) != 1 || len(repo.batches[0]) != 2 {
		t.Fatalf("batches = %#v", repo.batches)
	}
}

func TestWorkerDropsFailedBatch(t *testing.T) {
	repo := &repositoryStub{err: errors.New("copy failed")}
	buffer := service.NewMemoryPositionBuffer(10)
	worker, err := New(buffer, repo, Config{BatchSize: 2}, zap.NewNop())
	if err != nil {
		t.Fatalf("new worker: %v", err)
	}
	_ = buffer.Add(&models.Position{Sequence: 1})
	_ = buffer.Add(&models.Position{Sequence: 2})

	worker.flushAll(context.Background())
	if buffer.Len() != 0 {
		t.Fatalf("failed batch returned to buffer: len = %d", buffer.Len())
	}
}
