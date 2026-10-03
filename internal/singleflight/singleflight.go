// Package singleflight ensures at most one concurrent execution of a
// keyed function runs at a time; concurrent callers for the same key block
// and share the first call's result. Used so that N docker clients pulling
// the same layer at once trigger exactly one upstream fetch.
package singleflight

import "sync"

// Group deduplicates concurrent calls that share a key.
type Group struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	wg  sync.WaitGroup
	err error
}

// NewGroup creates an empty Group.
func NewGroup() *Group { return &Group{m: make(map[string]*call)} }

// Do executes fn for key, or waits for and returns the result of an
// in-flight call already running for the same key.
func (g *Group) Do(key string, fn func() error) error {
	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.err
	}
	c := &call{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.err
}
