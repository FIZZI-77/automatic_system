package service

import (
	"sync"

	"location/models"
)

type PositionBuffer interface {
	PositionHistorySink
	// TakeBatch удаляет и возвращает первые maxSize точек; неположительный размер означает все точки.
	TakeBatch(maxSize int) []*models.Position
	// Prepend возвращает пакет в начало очереди для повторной записи истории.
	Prepend(batch []*models.Position)
	// Len возвращает текущее количество точек в очереди.
	Len() int
}

type MemoryPositionBuffer struct {
	mu       sync.Mutex
	items    []*models.Position
	capacity int
}

// NewMemoryPositionBuffer создаёт безопасный для параллельных вызовов буфер точек.
// Неположительную capacity заменяет на 10 000.
func NewMemoryPositionBuffer(capacity int) *MemoryPositionBuffer {

	if capacity <= 0 {
		capacity = 10_000
	}

	return &MemoryPositionBuffer{items: make([]*models.Position, 0, capacity), capacity: capacity}
}

// Add добавляет указатель на точку в конец очереди без копирования модели.
// nil точка даёт ErrValidation, достижение capacity — ErrPositionBufferFull.
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

// TakeBatch удаляет из очереди до maxSize первых точек и возвращает новый срез указателей.
// Неположительный или превышающий длину размер означает весь буфер; пустой буфер даёт nil.
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

// Prepend добавляет указатели batch в начало очереди в исходном порядке.
// Лимит capacity и nil элементы не проверяет, позволяя вернуть неудачно записанный пакет.
func (b *MemoryPositionBuffer) Prepend(batch []*models.Position) {

	if len(batch) == 0 {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	items := make([]*models.Position, 0, len(batch)+len(b.items))
	items = append(items, batch...)
	items = append(items, b.items...)
	b.items = items
}

// Len возвращает число точек в очереди под блокировкой буфера.
func (b *MemoryPositionBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}
