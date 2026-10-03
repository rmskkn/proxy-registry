package singleflight

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupDedupesConcurrentCalls(t *testing.T) {
	g := NewGroup()
	var calls int32

	var wg sync.WaitGroup
	results := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = g.Do("same-key", func() error {
				atomic.AddInt32(&calls, 1)
				time.Sleep(20 * time.Millisecond)
				return nil
			})
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("fn called %d times, want exactly 1", got)
	}
	for i, err := range results {
		if err != nil {
			t.Errorf("caller %d got error %v, want nil", i, err)
		}
	}
}

func TestGroupPropagatesError(t *testing.T) {
	g := NewGroup()
	wantErr := errBoom
	err := g.Do("key", func() error { return wantErr })
	if err != wantErr {
		t.Errorf("got %v, want %v", err, wantErr)
	}
}

func TestGroupRunsAgainAfterCompletion(t *testing.T) {
	g := NewGroup()
	var calls int32
	for i := 0; i < 3; i++ {
		g.Do("key", func() error {
			atomic.AddInt32(&calls, 1)
			return nil
		})
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("fn called %d times across sequential calls, want 3", got)
	}
}

var errBoom = &sentinelError{"boom"}

type sentinelError struct{ msg string }

func (e *sentinelError) Error() string { return e.msg }
