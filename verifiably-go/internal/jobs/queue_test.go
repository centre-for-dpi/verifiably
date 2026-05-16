package jobs

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// newTestQueue returns a Queue wired to an in-memory store (pool=nil).
func newTestQueue(ctx context.Context, workers int) *Queue {
	return NewQueue(ctx, nil, workers)
}

// workOK is a workFn that succeeds immediately.
func workOK(_ context.Context, _ map[string]string) error { return nil }

// workFail is a workFn that always returns an error.
func workFail(_ context.Context, _ map[string]string) error {
	return fmt.Errorf("injected error")
}

// workSlow is a workFn that blocks until ctx is cancelled.
func workSlow(ctx context.Context, _ map[string]string) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestSubmitAndWait(t *testing.T) {
	ctx := context.Background()
	q := newTestQueue(ctx, 2)

	rows := Rows{{"name": "Alice"}, {"name": "Bob"}}
	var called atomic.Int32
	workFn := func(_ context.Context, _ map[string]string) error {
		called.Add(1)
		return nil
	}

	id, err := q.Submit(ctx, rows, workFn)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if id == "" {
		t.Fatal("Submit returned empty job ID")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		j, ok := q.Status(ctx, id)
		if ok && j.Status == StatusDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	j, ok := q.Status(ctx, id)
	if !ok {
		t.Fatal("Status: job not found")
	}
	if j.Status != StatusDone {
		t.Errorf("expected status %q, got %q", StatusDone, j.Status)
	}
	if j.Done != 2 {
		t.Errorf("expected Done=2, got %d", j.Done)
	}
	if j.Errors != 0 {
		t.Errorf("expected Errors=0, got %d", j.Errors)
	}
	if int(called.Load()) != 2 {
		t.Errorf("workFn called %d times, want 2", called.Load())
	}
}

func TestSubmitCountsErrors(t *testing.T) {
	ctx := context.Background()
	q := newTestQueue(ctx, 1)

	rows := Rows{{"a": "1"}, {"a": "2"}, {"a": "3"}}
	id, err := q.Submit(ctx, rows, workFail)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := q.Status(ctx, id)
		if j.Status == StatusDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	j, _ := q.Status(ctx, id)
	if j.Errors != 3 {
		t.Errorf("expected Errors=3, got %d", j.Errors)
	}
}

func TestSubscriberReceivesProgress(t *testing.T) {
	ctx := context.Background()
	q := newTestQueue(ctx, 1)

	rows := Rows{{"x": "1"}, {"x": "2"}}
	subCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	id, err := q.Submit(ctx, rows, workOK)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	ch := q.Subscribe(subCtx, id)
	var received []Progress
	for p := range ch {
		received = append(received, p)
		if p.Status == StatusDone {
			break
		}
	}

	if len(received) == 0 {
		t.Fatal("no progress events received")
	}
	last := received[len(received)-1]
	if last.Status != StatusDone {
		t.Errorf("last progress status = %q, want %q", last.Status, StatusDone)
	}
}

func TestContextCancelCleansUpSubscriber(t *testing.T) {
	ctx := context.Background()
	q := newTestQueue(ctx, 1)

	rows := Rows{{"x": "1"}}
	id, _ := q.Submit(ctx, rows, workOK)

	subCtx, cancel := context.WithCancel(ctx)
	ch := q.Subscribe(subCtx, id)
	cancel() // cancel immediately

	// Channel must be closed (no leak).
	select {
	case _, open := <-ch:
		if open {
			// Drain any progress that arrived before cancel.
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("subscriber channel not closed after context cancel")
	}
}

func TestQueueFull(t *testing.T) {
	// Create a queue with 1 worker that is kept busy by workSlow.
	slowCtx, slowCancel := context.WithCancel(context.Background())
	defer slowCancel()
	q := NewQueue(slowCtx, nil, 1)

	// Fill the pending buffer (256 slots) plus the worker slot.
	blockRow := Rows{{"block": "1"}}
	_ , _ = q.Submit(slowCtx, blockRow, workSlow) // occupies the worker

	ctx := context.Background()
	for i := 0; i < 256; i++ {
		_, _ = q.Submit(ctx, Rows{{"i": fmt.Sprintf("%d", i)}}, workOK)
	}

	// The 258th submission should fail with "queue full".
	_, err := q.Submit(ctx, Rows{{"overflow": "1"}}, workOK)
	if err == nil {
		t.Error("expected error on full queue, got nil")
	}
}

func TestShutdownContextAbortsRun(t *testing.T) {
	shutCtx, shutCancel := context.WithCancel(context.Background())
	q := NewQueue(shutCtx, nil, 1)

	// A slow job that blocks on the context.
	rows := make(Rows, 10)
	for i := range rows {
		rows[i] = map[string]string{"i": fmt.Sprintf("%d", i)}
	}

	id, err := q.Submit(shutCtx, rows, workSlow)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// Let the worker start.
	time.Sleep(50 * time.Millisecond)

	// Cancel the shutdown context.
	shutCancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := q.Status(context.Background(), id)
		if j.Status == StatusError {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	j, _ := q.Status(context.Background(), id)
	if j.Status != StatusError {
		t.Errorf("expected status %q after shutdown, got %q", StatusError, j.Status)
	}
}
