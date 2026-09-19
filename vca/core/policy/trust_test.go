// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// trustAll returns a lookup that trusts every issuer.
func trustAll(context.Context, string, string) (Trust, error) {
	return Trust{Trusted: true, DisplayName: "Ministry", ListURL: "https://trust.example/list"}, nil
}

func TestTrustChainNoCredentials(t *testing.T) {
	wantOutcome(t, only(t, trustChain(context.Background(), Presentation{}, base())), Skip)
}

func TestTrustChainTrusted(t *testing.T) {
	pc := base()
	pc.Trust = trustAll
	got := trustChain(context.Background(), pres(objectCred(vc.FormatJSONLD, map[string]any{"issuer": "did:web:a"})), pc)
	if len(got) != 2 {
		t.Fatalf("want an issuer result and a chain result, got %d", len(got))
	}
	wantOutcome(t, got[0], Pass)
	if got[0].Evidence["issuer_name"] != "Ministry" {
		t.Fatalf("want the issuer name as evidence, got %v", got[0].Evidence)
	}
	wantOutcome(t, got[1], Skip)
}

func TestTrustChainUntrusted(t *testing.T) {
	pc := base()
	pc.Trust = func(context.Context, string, string) (Trust, error) {
		return Trust{Reason: "the accreditation ended"}, nil
	}
	got := trustChain(context.Background(), pres(objectCred(vc.FormatJSONLD, nil)), pc)
	wantOutcome(t, got[0], Fail)
	if got[0].Evidence["reason"] != "the accreditation ended" {
		t.Fatalf("want the reason as evidence, got %v", got[0].Evidence)
	}
}

func TestTrustChainNoLookup(t *testing.T) {
	got := trustChain(context.Background(), pres(objectCred(vc.FormatJSONLD, nil)), base())
	wantOutcome(t, got[0], Error)
}

func TestTrustChainLookupFails(t *testing.T) {
	pc := base()
	pc.Trust = func(context.Context, string, string) (Trust, error) { return Trust{}, errors.New("offline") }
	got := trustChain(context.Background(), pres(objectCred(vc.FormatJSONLD, nil)), pc)
	wantOutcome(t, got[0], Error)
}

func TestChainLinkResolved(t *testing.T) {
	pc := base()
	pc.Trust = trustAll
	root := objectCred(vc.FormatJSONLD, map[string]any{"id": "urn:root", "issuer": "did:web:a"})
	child := objectCred(vc.FormatJSONLD, map[string]any{
		"id": "urn:child", "issuer": "did:web:a",
		"parentCredential": map[string]any{"id": "urn:root"},
	})
	got := trustChain(context.Background(), pres(root, child), pc)
	wantOutcome(t, got[len(got)-1], Pass)
}

func TestChainLinkBroken(t *testing.T) {
	pc := base()
	pc.Trust = trustAll
	child := objectCred(vc.FormatJSONLD, map[string]any{"id": "urn:child", "parentCredential": "urn:missing"})
	got := trustChain(context.Background(), pres(child), pc)
	last := got[len(got)-1]
	wantOutcome(t, last, Fail)
	if last.Evidence["missing"] != "urn:missing" {
		t.Fatalf("want the missing id as evidence, got %v", last.Evidence)
	}
}

func TestChainLinkRequired(t *testing.T) {
	pc := base()
	pc.Params = map[string]string{ParamRequireChain: "true"}
	wantOutcome(t, chainLink(pres(objectCred(vc.FormatJSONLD, nil)), pc), Fail)
}

func TestChainRefShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{"none", map[string]any{}, ""},
		{"top level", map[string]any{"parentCredential": "urn:a"}, "urn:a"},
		{"subject", map[string]any{"credentialSubject": map[string]any{"parentCredential": "urn:b"}}, "urn:b"},
		{"subject without link", map[string]any{"credentialSubject": map[string]any{}}, ""},
		{"delegation claim", map[string]any{"delegation": map[string]any{"parent_capability": "urn:c"}}, "urn:c"},
		{"terms of use", map[string]any{"termsOfUse": []any{map[string]any{"parentCapability": "urn:d"}}}, "urn:d"},
		{"terms of use not an object", map[string]any{"termsOfUse": []any{"text"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := chainRef(vc.Credential{Raw: tc.raw}); got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestRefIDAndSlice(t *testing.T) {
	if got := refID(7); got != "" {
		t.Fatalf("want no id from a number, got %q", got)
	}
	if got := asSlice(nil); got != nil {
		t.Fatalf("want no items, got %v", got)
	}
	if got := asSlice("one"); len(got) != 1 {
		t.Fatalf("want one item, got %v", got)
	}
}
