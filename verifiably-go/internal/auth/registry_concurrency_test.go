package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

// stubProvider satisfies Provider with the minimum needed for Registry tests.
type stubProvider struct {
	id     string
	source string
}

func (s stubProvider) ID() string          { return s.id }
func (s stubProvider) DisplayName() string { return s.id }
func (s stubProvider) Kind() string        { return "OIDC" }
func (s stubProvider) Source() string      { return s.source }
func (s stubProvider) AuthorizeURL(_ context.Context, _, _, _ string) (string, error) {
	return "", nil
}
func (s stubProvider) Exchange(_ context.Context, _, _, _ string) (Token, error) {
	return Token{}, nil
}
func (s stubProvider) Refresh(_ context.Context, _ string) (Token, error) {
	return Token{}, nil
}
func (s stubProvider) UserInfo(_ context.Context, _ string) (UserInfo, error) {
	return UserInfo{}, nil
}
func (s stubProvider) ServeLogout(http.ResponseWriter, *http.Request) {}

// TestRegistry_Remove covers the admin "delete provider" UX. Returns true
// when a row goes away, false when nothing matched (idempotent retry).
func TestRegistry_Remove(t *testing.T) {
	r := NewRegistry()
	r.Register(stubProvider{id: "a"})
	r.Register(stubProvider{id: "b"})

	if !r.Remove("a") {
		t.Fatal("Remove(\"a\") returned false on first call")
	}
	if r.Remove("a") {
		t.Fatal("Remove(\"a\") returned true on a second call (should be idempotent)")
	}
	if got := len(r.All()); got != 1 {
		t.Fatalf("expected 1 remaining provider, got %d", got)
	}
	if r.Lookup("a") != nil {
		t.Fatal("a should be unreachable via Lookup after Remove")
	}
	if r.Lookup("b") == nil {
		t.Fatal("Remove dropped the wrong row")
	}
}

// TestRegistry_DescriptorsCarrySource pins the Source pass-through. Used
// by the admin UI to render the "managed by deploy" pill (system rows)
// vs the edit/delete buttons (user rows).
func TestRegistry_DescriptorsCarrySource(t *testing.T) {
	r := NewRegistry()
	r.Register(stubProvider{id: "k", source: SourceSystem})
	r.Register(stubProvider{id: "u", source: SourceUser})
	got := r.Descriptors()
	if len(got) != 2 {
		t.Fatalf("got %d descriptors, want 2", len(got))
	}
	for _, d := range got {
		switch d.ID {
		case "k":
			if d.Source != SourceSystem {
				t.Errorf("k.Source = %q, want %q", d.Source, SourceSystem)
			}
		case "u":
			if d.Source != SourceUser {
				t.Errorf("u.Source = %q, want %q", d.Source, SourceUser)
			}
		}
	}
}

// TestRegistry_RegisterReplacesSameID covers the runtime "Add OIDC provider"
// UX: re-submitting the form with the same display name (slug) updates the
// existing provider in place, so the operator can iterate on a misconfigured
// IdP without restart-thrash.
func TestRegistry_RegisterReplacesSameID(t *testing.T) {
	r := NewRegistry()
	r.Register(stubProvider{id: "custom"})
	r.Register(stubProvider{id: "custom"})
	if got := len(r.All()); got != 1 {
		t.Errorf("expected one entry after replace, got %d", got)
	}
}

// TestRegistry_ConcurrentReadWrite guards the Mutex added to Registry.
// Without it, the auth-page render (Descriptors / Lookup) racing with a
// runtime /auth/custom POST (Register) trips Go's race detector.
func TestRegistry_ConcurrentReadWrite(t *testing.T) {
	r := NewRegistry()
	r.Register(stubProvider{id: "seed"})

	const writers, readers, ops = 4, 8, 200
	var wg sync.WaitGroup

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				r.Register(stubProvider{id: "p" + string(rune('a'+i))})
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				_ = r.Descriptors()
				_ = r.Lookup("seed")
				_ = r.All()
			}
		}()
	}
	wg.Wait()

	// At minimum the seed plus one entry per writer should exist.
	if got := len(r.All()); got < writers+1 {
		t.Errorf("expected at least %d entries, got %d", writers+1, got)
	}
}
