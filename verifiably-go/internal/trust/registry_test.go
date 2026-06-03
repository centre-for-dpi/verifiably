package trust

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ── TrustedIssuer value methods ───────────────────────────────────────────────

func TestIsExpired(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		e       TrustedIssuer
		expired bool
	}{
		{"zero ValidUntil never expires", TrustedIssuer{}, false},
		{"future ValidUntil not expired", TrustedIssuer{ValidUntil: now.Add(24 * time.Hour)}, false},
		{"past ValidUntil is expired", TrustedIssuer{ValidUntil: now.Add(-time.Second)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.e.IsExpired() != tc.expired {
				t.Errorf("IsExpired() = %v, want %v", tc.e.IsExpired(), tc.expired)
			}
		})
	}
}

func TestAuthorisesSchema(t *testing.T) {
	cases := []struct {
		name     string
		schemas  []string
		schemaID string
		want     bool
	}{
		{"empty schemas = wildcard", nil, "AnyCred", true},
		{"empty slice = wildcard", []string{}, "AnyCred", true},
		{"matching schema", []string{"DNI", "Passport"}, "Passport", true},
		{"non-matching schema", []string{"DNI", "Passport"}, "DriversLicense", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := TrustedIssuer{Schemas: tc.schemas}
			if got := e.AuthorisesSchema(tc.schemaID); got != tc.want {
				t.Errorf("AuthorisesSchema(%q) = %v, want %v", tc.schemaID, got, tc.want)
			}
		})
	}
}

// ── memStore ──────────────────────────────────────────────────────────────────

func newTestStore() Registry { return NewMemStore() }

func TestMemStore_AddAndTrustedIssuers(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	if err := s.Add(ctx, TrustedIssuer{DID: "did:web:a.gov", DisplayName: "A"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Add(ctx, TrustedIssuer{DID: "did:web:b.gov", DisplayName: "B"}); err != nil {
		t.Fatalf("Add second: %v", err)
	}

	list, err := s.TrustedIssuers(ctx)
	if err != nil {
		t.Fatalf("TrustedIssuers: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 issuers, got %d", len(list))
	}
}

func TestMemStore_SortedByDID(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:z.gov"})
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:a.gov"})
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:m.gov"})

	list, _ := s.TrustedIssuers(ctx)
	for i := 1; i < len(list); i++ {
		if list[i].DID < list[i-1].DID {
			t.Errorf("TrustedIssuers not sorted: %q before %q", list[i-1].DID, list[i].DID)
		}
	}
}

func TestMemStore_AddSetsAccreditedAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:x.gov"})
	list, _ := s.TrustedIssuers(ctx)
	if list[0].AccreditedAt.IsZero() {
		t.Error("AccreditedAt should be auto-set on Add")
	}
}

func TestMemStore_AddReplaces(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:a.gov", DisplayName: "Old"})
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:a.gov", DisplayName: "New"})
	list, _ := s.TrustedIssuers(ctx)
	if len(list) != 1 {
		t.Fatalf("expected 1 issuer after upsert, got %d", len(list))
	}
	if list[0].DisplayName != "New" {
		t.Errorf("expected DisplayName=New, got %q", list[0].DisplayName)
	}
}

func TestMemStore_Remove(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:a.gov"})
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:b.gov"})
	if err := s.Remove(ctx, "did:web:a.gov"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	list, _ := s.TrustedIssuers(ctx)
	if len(list) != 1 || list[0].DID != "did:web:b.gov" {
		t.Errorf("expected only b.gov after removal, got %v", list)
	}
}

func TestMemStore_RemoveNoop(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	if err := s.Remove(ctx, "did:web:nobody.gov"); err != nil {
		t.Errorf("Remove of missing DID should be a no-op, got: %v", err)
	}
}

func TestMemStore_IsTrusted_NotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	err := s.IsTrusted(ctx, "did:web:unknown.gov", "DNI")
	if !errors.Is(err, ErrUntrusted) {
		t.Errorf("IsTrusted on unknown DID: want ErrUntrusted, got %v", err)
	}
}

func TestMemStore_IsTrusted_Expired(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{
		DID:        "did:web:expired.gov",
		ValidUntil: time.Now().Add(-time.Hour),
	})
	err := s.IsTrusted(ctx, "did:web:expired.gov", "DNI")
	if !errors.Is(err, ErrUntrusted) {
		t.Errorf("IsTrusted on expired issuer: want ErrUntrusted, got %v", err)
	}
}

func TestMemStore_IsTrusted_WrongSchema(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{
		DID:     "did:web:issuer.gov",
		Schemas: []string{"Passport"},
	})
	err := s.IsTrusted(ctx, "did:web:issuer.gov", "DriversLicense")
	if !errors.Is(err, ErrUntrusted) {
		t.Errorf("IsTrusted with wrong schema: want ErrUntrusted, got %v", err)
	}
}

func TestMemStore_IsTrusted_Success(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{
		DID:     "did:web:issuer.gov",
		Schemas: []string{"DNI", "Passport"},
	})
	if err := s.IsTrusted(ctx, "did:web:issuer.gov", "DNI"); err != nil {
		t.Errorf("IsTrusted on valid issuer+schema: want nil, got %v", err)
	}
}

func TestMemStore_IsTrusted_Wildcard(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.Add(ctx, TrustedIssuer{DID: "did:web:issuer.gov"}) // no Schemas = wildcard
	if err := s.IsTrusted(ctx, "did:web:issuer.gov", "AnythingAtAll"); err != nil {
		t.Errorf("IsTrusted with wildcard schemas: want nil, got %v", err)
	}
}
