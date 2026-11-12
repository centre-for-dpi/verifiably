package pg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const testDSN = "postgres://u:p@127.0.0.1:5432/db?sslmode=disable"

func withOpen(t *testing.T, fn func(context.Context, string) (*pgxpool.Pool, error)) {
	t.Helper()
	old := openFn
	openFn = fn
	t.Cleanup(func() { openFn = old })
}

func TestOpenWithRetryBadDSNFailsFast(t *testing.T) {
	calls := 0
	withOpen(t, func(context.Context, string) (*pgxpool.Pool, error) { calls++; return nil, errors.New("x") })
	start := time.Now()
	if _, err := OpenWithRetry(context.Background(), "postgres://bad dsn:%%", time.Minute, nil); err == nil {
		t.Fatal("want an error for an unparseable DSN")
	}
	if calls != 0 || time.Since(start) > time.Second {
		t.Fatalf("an unparseable DSN must not be retried (calls=%d, took %s)", calls, time.Since(start))
	}
}

func TestOpenWithRetrySucceedsAfterFailures(t *testing.T) {
	calls := 0
	withOpen(t, func(context.Context, string) (*pgxpool.Pool, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("connection refused")
		}
		return &pgxpool.Pool{}, nil
	})
	logged := 0
	pool, err := OpenWithRetry(context.Background(), testDSN, 30*time.Second, func(string, ...any) { logged++ })
	if err != nil || pool == nil {
		t.Fatalf("want success on the 3rd attempt, got pool=%v err=%v", pool, err)
	}
	if calls != 3 || logged != 2 {
		t.Fatalf("calls=%d logged=%d, want 3 and 2", calls, logged)
	}
}

func TestOpenWithRetryGivesUpAfterWait(t *testing.T) {
	calls := 0
	withOpen(t, func(context.Context, string) (*pgxpool.Pool, error) {
		calls++
		return nil, errors.New("connection refused")
	})
	start := time.Now()
	_, err := OpenWithRetry(context.Background(), testDSN, 2500*time.Millisecond, nil)
	if err == nil {
		t.Fatal("want an error once the wait is exhausted")
	}
	if took := time.Since(start); took > 4*time.Second {
		t.Fatalf("took %s, want it to stop near the 2.5s wait", took)
	}
	if calls < 2 {
		t.Fatalf("calls=%d, want at least one retry", calls)
	}
}

func TestOpenWithRetryStopsOnCancel(t *testing.T) {
	withOpen(t, func(context.Context, string) (*pgxpool.Pool, error) { return nil, errors.New("connection refused") })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := OpenWithRetry(ctx, testDSN, time.Minute, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
