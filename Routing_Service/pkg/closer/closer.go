package closer

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type item struct {
	name string
	fn   func() error
}
type Closer struct {
	mu    sync.Mutex
	once  sync.Once
	items []item
	err   error
}

func New() *Closer { return &Closer{} }
func (c *Closer) Add(name string, fn func() error) {
	if fn == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, item{name: name, fn: fn})
}
func (c *Closer) Close(ctx context.Context) error {
	c.once.Do(func() { c.err = c.closeAll(ctx) })
	return c.err
}
func (c *Closer) closeAll(ctx context.Context) error {
	c.mu.Lock()
	items := append([]item(nil), c.items...)
	c.mu.Unlock()
	var result error
	for i := len(items) - 1; i >= 0; i-- {
		done := make(chan error, 1)
		go func(current item) { done <- current.fn() }(items[i])
		select {
		case err := <-done:
			if err != nil {
				result = errors.Join(result, fmt.Errorf("%s: %w", items[i].name, err))
			}
		case <-ctx.Done():
			return errors.Join(result, ctx.Err())
		}
	}
	return result
}
