package closer

import (
	"context"
	"reflect"
	"testing"
)

func TestCloserClosesDependenciesInReverseOrderOnce(t *testing.T) {
	closer := New()
	var order []string
	closer.Add("postgres", func() error { order = append(order, "postgres"); return nil })
	closer.Add("redis", func() error { order = append(order, "redis"); return nil })
	closer.Add("stream", func() error { order = append(order, "stream"); return nil })

	if err := closer.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := closer.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
	want := []string{"stream", "redis", "postgres"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("close order = %#v, want %#v", order, want)
	}
}
