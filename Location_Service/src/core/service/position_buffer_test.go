package service

import (
	"errors"
	"testing"

	"location/models"
)

func TestMemoryPositionBufferFIFOAndCapacity(t *testing.T) {
	buffer := NewMemoryPositionBuffer(2)
	first := &models.Position{Sequence: 1}
	second := &models.Position{Sequence: 2}

	if err := buffer.Add(first); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if err := buffer.Add(second); err != nil {
		t.Fatalf("add second: %v", err)
	}
	if err := buffer.Add(&models.Position{Sequence: 3}); !errors.Is(
		err,
		models.ErrPositionBufferFull,
	) {
		t.Fatalf("add over capacity error = %v", err)
	}

	batch := buffer.TakeBatch(1)
	if len(batch) != 1 || batch[0] != first {
		t.Fatalf("first batch = %#v", batch)
	}
	batch = buffer.TakeBatch(10)
	if len(batch) != 1 || batch[0] != second || buffer.Len() != 0 {
		t.Fatalf("second batch = %#v, remaining = %d", batch, buffer.Len())
	}
}
