package service

import (
	"sync"

	"location/models"
)

type PositionBuffer interface {
	PositionHistorySink
	TakeBatch(maxSize int) []*models.Position
	Len() int
}

type MemoryPositionBuffer struct {
	mu       sync.Mutex
	items    []*models.Position
	capacity int
}

func NewMemoryPositionBuffer(capacity int) *MemoryPositionBuffer {
	if capacity <= 0 {
		capacity = 10_000
	}
	return &MemoryPositionBuffer{items: make([]*models.Position, 0, capacity), capacity: capacity}
}

func (b *MemoryPositionBuffer) Add(position *models.Position) error {
	if position == nil {
		return models.ErrValidation
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) >= b.capacity {
		return models.ErrPositionBufferFull
	}
	b.items = append(b.items, position)
	return nil
}

func (b *MemoryPositionBuffer) TakeBatch(maxSize int) []*models.Position {
	b.mu.Lock()
	defer b.mu.Unlock()
	if maxSize <= 0 || maxSize > len(b.items) {
		maxSize = len(b.items)
	}
	if maxSize == 0 {
		return nil
	}
	batch := append([]*models.Position(nil), b.items[:maxSize]...)
	clear(b.items[:maxSize])
	b.items = append(b.items[:0], b.items[maxSize:]...)
	return batch
}

func (b *MemoryPositionBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}
