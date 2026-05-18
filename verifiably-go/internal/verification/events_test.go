package verification

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ── memLog ────────────────────────────────────────────────────────────────────
// In-memory Log implementation for testing without a database.

type memLog struct {
	mu     sync.Mutex
	events []Event
}

func newMemLog() Log { return &memLog{} }

func (l *memLog) Append(_ context.Context, e Event) error {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
	return nil
}

func (l *memLog) QueryByIssuer(_ context.Context, issuerDID string, period time.Duration) ([]Event, error) {
	cutoff := time.Now().Add(-period)
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.events {
		if e.IssuerDID == issuerDID && e.VerifiedAt.After(cutoff) {
			out = append(out, e)
		}
	}
	return out, nil
}

// ── NewID ─────────────────────────────────────────────────────────────────────

func TestNewID_Length(t *testing.T) {
	id := NewID()
	if len(id) != 24 {
		t.Errorf("NewID() length = %d, want 24", len(id))
	}
}

func TestNewID_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := NewID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID generated at iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestNewID_HexChars(t *testing.T) {
	id := NewID()
	for i, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("NewID contains non-hex char %q at position %d", c, i)
		}
	}
}

// ── memLog contract tests ─────────────────────────────────────────────────────

func TestMemLog_AppendAndQuery(t *testing.T) {
	ctx := context.Background()
	l := newMemLog()

	e := Event{
		ID:        NewID(),
		IssuerDID: "did:web:issuer.gov",
		SchemaID:  "DNI",
		Status:    "valid",
		VerifiedAt: time.Now(),
	}
	if err := l.Append(ctx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	results, err := l.QueryByIssuer(ctx, "did:web:issuer.gov", 24*time.Hour)
	if err != nil {
		t.Fatalf("QueryByIssuer: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != e.ID {
		t.Errorf("result ID = %q, want %q", results[0].ID, e.ID)
	}
}

func TestMemLog_QueryFiltersOldEvents(t *testing.T) {
	ctx := context.Background()
	l := newMemLog()

	old := Event{
		ID:         NewID(),
		IssuerDID:  "did:web:issuer.gov",
		Status:     "valid",
		VerifiedAt: time.Now().Add(-48 * time.Hour),
	}
	recent := Event{
		ID:         NewID(),
		IssuerDID:  "did:web:issuer.gov",
		Status:     "valid",
		VerifiedAt: time.Now(),
	}
	_ = l.Append(ctx, old)
	_ = l.Append(ctx, recent)

	results, _ := l.QueryByIssuer(ctx, "did:web:issuer.gov", 24*time.Hour)
	if len(results) != 1 {
		t.Fatalf("expected 1 result (old event filtered), got %d", len(results))
	}
	if results[0].ID != recent.ID {
		t.Errorf("expected recent event, got %q", results[0].ID)
	}
}

func TestMemLog_QueryFiltersWrongIssuer(t *testing.T) {
	ctx := context.Background()
	l := newMemLog()

	_ = l.Append(ctx, Event{
		ID:         NewID(),
		IssuerDID:  "did:web:a.gov",
		Status:     "valid",
		VerifiedAt: time.Now(),
	})

	results, _ := l.QueryByIssuer(ctx, "did:web:b.gov", 24*time.Hour)
	if len(results) != 0 {
		t.Errorf("expected 0 results for unknown issuer, got %d", len(results))
	}
}

func TestMemLog_MultipleIssuers(t *testing.T) {
	ctx := context.Background()
	l := newMemLog()

	for i := 0; i < 3; i++ {
		_ = l.Append(ctx, Event{
			ID:         NewID(),
			IssuerDID:  "did:web:a.gov",
			Status:     "valid",
			VerifiedAt: time.Now(),
		})
	}
	_ = l.Append(ctx, Event{
		ID:         NewID(),
		IssuerDID:  "did:web:b.gov",
		Status:     "invalid",
		VerifiedAt: time.Now(),
	})

	aResults, _ := l.QueryByIssuer(ctx, "did:web:a.gov", 24*time.Hour)
	if len(aResults) != 3 {
		t.Errorf("expected 3 events for a.gov, got %d", len(aResults))
	}
	bResults, _ := l.QueryByIssuer(ctx, "did:web:b.gov", 24*time.Hour)
	if len(bResults) != 1 {
		t.Errorf("expected 1 event for b.gov, got %d", len(bResults))
	}
}

func TestMemLog_EmptyForUnknownIssuer(t *testing.T) {
	ctx := context.Background()
	l := newMemLog()
	results, err := l.QueryByIssuer(ctx, "did:web:nobody.gov", 24*time.Hour)
	if err != nil {
		t.Fatalf("QueryByIssuer on empty log: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}
}
