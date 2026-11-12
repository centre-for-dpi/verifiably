package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// openFn is Open, swappable in tests.
var openFn = Open

// OpenWithRetry calls Open until it succeeds or `wait` has elapsed.
//
// After a host reboot (or a `docker compose up` without health-gated
// depends_on) verifiably-go often starts a few seconds before PostgreSQL
// accepts connections. A single attempt then fails and the caller would fall
// back to file-backed stores, silently putting the trust registry, issuance
// log and status lists somewhere other than the database the operator
// configured. Retrying for a bounded time removes that race.
//
// A DSN that does not parse is reported immediately (retrying cannot fix it).
// Waits between attempts start at 1s and double up to 5s. logf, when non-nil,
// is called before each wait so the operator can see progress.
func OpenWithRetry(ctx context.Context, dsn string, wait time.Duration, logf func(format string, args ...any)) (*pgxpool.Pool, error) {
	if _, err := pgxpool.ParseConfig(dsn); err != nil {
		return nil, fmt.Errorf("pg: parse DSN: %w", err)
	}
	deadline := time.Now().Add(wait)
	delay := time.Second
	for attempt := 1; ; attempt++ {
		pool, err := openFn(ctx, dsn)
		if err == nil {
			return pool, nil
		}
		if time.Now().Add(delay).After(deadline) {
			return nil, fmt.Errorf("pg: still unreachable after %d attempt(s) over %s: %w", attempt, wait, err)
		}
		if logf != nil {
			logf("pg: attempt %d failed (%v); retrying in %s", attempt, err, delay)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay *= 2
			if delay > 5*time.Second {
				delay = 5 * time.Second
			}
		}
	}
}
