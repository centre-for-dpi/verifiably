package verifiably

import (
	"context"
	"encoding/json"
	"testing"
)

// The verifiably adapter is the federation Hub's client for a *remote*
// verifiably-go member: it delegates OID4VP and nothing else. Its catalog and
// schema methods are deliberate stubs — a member's own DPG list is not the
// Hub's to advertise — and returning nil, nil rather than ErrNotSupported is
// what keeps the Hub's aggregate catalog from erroring when a member is
// verifier-only.
func TestCatalogStubsAreEmptyNotErrors(t *testing.T) {
	a, err := New(Config{ServiceEndpoint: "https://member.example"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if m, err := a.ListIssuerDpgs(ctx); err != nil || len(m) != 0 {
		t.Errorf("ListIssuerDpgs = %v, %v; want empty, nil", m, err)
	}
	if m, err := a.ListHolderDpgs(ctx); err != nil || len(m) != 0 {
		t.Errorf("ListHolderDpgs = %v, %v; want empty, nil", m, err)
	}
	if m, err := a.ListVerifierDpgs(ctx); err != nil || len(m) != 0 {
		t.Errorf("ListVerifierDpgs = %v, %v; want empty, nil", m, err)
	}
}

// A member with no serviceEndpoint cannot be routed to, so the Hub must refuse
// it at construction rather than producing an adapter that fails on every call.
func TestNew_RequiresServiceEndpoint(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected an error when serviceEndpoint is missing")
	}
	if _, err := New(Config{ServiceEndpoint: "https://member.example", APIKey: "k"}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestUnmarshalConfig(t *testing.T) {
	c, err := UnmarshalConfig(json.RawMessage(`{"serviceEndpoint":"https://m.example","apiKey":"k1"}`))
	if err != nil {
		t.Fatalf("UnmarshalConfig: %v", err)
	}
	if c.ServiceEndpoint != "https://m.example" || c.APIKey != "k1" {
		t.Errorf("config = %+v", c)
	}

	// An absent verifierConfig in federation.json is valid — the member may be
	// issuer-only — so an empty blob must not error.
	if _, err := UnmarshalConfig(nil); err != nil {
		t.Errorf("empty config must not error: %v", err)
	}
	if _, err := UnmarshalConfig(json.RawMessage(`{oops`)); err == nil {
		t.Error("malformed config must error")
	}
}
