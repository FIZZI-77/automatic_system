package closer

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type closeFunc struct {
	name string
	fn   func() error
}

type Closer struct {
	mu    sync.Mutex
	once  sync.Once
	funcs []closeFunc
	err   error
}

func New() *Closer {
	return &Closer{}
}

func (c *Closer) Add(name string, fn func() error) {
	if fn == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.funcs = append(c.funcs, closeFunc{name: name, fn: fn})
}

func (c *Closer) Close(ctx context.Context) error {
	c.once.Do(func() {
		c.err = c.closeAll(ctx)
	})

	return c.err
}

func (c *Closer) closeAll(ctx context.Context) error {
	c.mu.Lock()
	funcs := append([]closeFunc(nil), c.funcs...)
	c.mu.Unlock()

	var result error
	for i := len(funcs) - 1; i >= 0; i-- {
		if err := closeWithContext(ctx, funcs[i]); err != nil {
			result = errors.Join(result, err)
		}
	}

	return result
}

func closeWithContext(ctx context.Context, item closeFunc) error {
	done := make(chan error, 1)
	go func() {
		done <- item.fn()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", item.name, ctx.Err())
	}
}
