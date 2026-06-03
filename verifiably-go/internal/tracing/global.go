package tracing

import (
	"context"
	"sync/atomic"
)

// global holds the process-wide tracer. Initialised to a no-op tracer so
// callers can safely use the package-level API before SetGlobal is called
// (e.g. during init() or in tests that don't configure tracing).
var global atomic.Pointer[Tracer]

func init() {
	noop := NewTracer("noop", 0, NoopExporter{})
	global.Store(noop)
}

// SetGlobal installs t as the process-wide tracer. Must be called before
// any HTTP handlers begin serving requests (typically in main() after the
// tracer is fully configured).
func SetGlobal(t *Tracer) {
	global.Store(t)
}

// Global returns the process-wide tracer.
func Global() *Tracer {
	return global.Load()
}

// Start is a package-level shortcut for Global().Start(ctx, name).
// Use in handlers and helpers that don't carry an explicit *Tracer reference.
func Start(ctx context.Context, name string) (context.Context, *Span) {
	return Global().Start(ctx, name)
}
