// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"time"
)

// Due returns the kinds whose refresh interval passed since their last
// run, in sync order. A kind that never ran is due.
func (c *Cache) Due(ctx context.Context) []Kind {
	p := c.Policy(ctx)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Kind
	for _, k := range Kinds() {
		last, ok := c.runs[k]
		if !ok || now.Sub(last) >= p.Refresh(k) {
			out = append(out, k)
		}
	}
	return out
}

// RunDue reads every due kind and returns the kinds it read.
func (c *Cache) RunDue(ctx context.Context) []Kind {
	due := c.Due(ctx)
	for _, k := range due {
		if _, err := c.Sync(ctx, k); err != nil {
			c.opts.Log.Error("cache: the scheduled read failed", "kind", k, "error", err)
		}
	}
	return due
}

// Run reads the due kinds now and then at every tick until ctx ends
// (ADR-041 decision 2).
func (c *Cache) Run(ctx context.Context, tick time.Duration) {
	c.RunDue(ctx)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.RunDue(ctx)
		}
	}
}
