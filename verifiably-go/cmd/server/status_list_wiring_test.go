package main

import (
	"context"
	"errors"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/handlers"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// issuerOnlyAdapter is a registry-shaped adapter that lists issuer DPGs and
// deliberately exposes NO signing key — i.e. the production shape of an
// Inji-only deployment. The embedded nil interface panics loudly on any
// method these tests don't expect to be called.
type issuerOnlyAdapter struct {
	backend.Adapter
	dpgs map[string]vctypes.DPG
}

func (a issuerOnlyAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return a.dpgs, nil
}

// noDpgAdapter has no issuer DPGs (a verifier-only or mock deployment).
type noDpgAdapter struct{ backend.Adapter }

func (noDpgAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return map[string]vctypes.DPG{}, nil
}

// erroringAdapter can't answer — e.g. a vendor that isn't up yet at boot.
type erroringAdapter struct{ backend.Adapter }

func (erroringAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return nil, errors.New("vendor unreachable")
}

func injiOnlyDPGs() map[string]vctypes.DPG {
	return map[string]vctypes.DPG{
		"Inji Certify · Pre-Auth":  {},
		"Inji Certify · Auth-Code": {},
		"CREDEBL":                  {},
		"walt.id":                  {},
	}
}

func wireForTest(t *testing.T, ad backend.Adapter) *handlers.H {
	t.Helper()
	dir := t.TempDir()
	h := &handlers.H{Adapter: ad}
	// Legacy defaults, exactly as wireIssuanceFile leaves them.
	bs, err := statuslist.NewStore("bitstring", "v1", dir+"/bs.json", "https://x.test/status-list/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := statuslist.NewStore("token", "v1", dir+"/tk.json", "https://x.test/status-list/token/v1")
	if err != nil {
		t.Fatal(err)
	}
	h.BitstringStore, h.TokenStore = bs, tk
	if err := wireStatusListSet(context.Background(), h, nil, "https://x.test", dir); err != nil {
		t.Fatalf("wireStatusListSet: %v", err)
	}
	return h
}

// THE regression test for the 503.
//
// Publishing a status list requires signing it. Signing used to resolve the
// key by type-asserting the issuer adapter for IssuerSigningKey, which only
// walt.id ever implemented — so a deployment registering only Inji adapters
// hosted lists it could not sign, and every fetch 503'd, which failed every
// revocation check closed.
//
// The invariant that makes that unrepresentable: if we host a list, we can
// sign it. Assert it over an adapter with no signing key whatsoever.
func TestWireStatusListSet_EveryHostedListHasASigner(t *testing.T) {
	h := wireForTest(t, issuerOnlyAdapter{dpgs: injiOnlyDPGs()})

	entries := h.StatusLists.Entries()
	if len(entries) == 0 {
		t.Fatal("no status lists registered")
	}
	for _, e := range entries {
		if e.Store == nil {
			t.Errorf("list %q: hosted with no store", e.Kind)
			continue
		}
		if e.Signer == nil {
			t.Errorf("list %q/%q (DPG %q): hosted but NOT signable — this is the 503",
				e.Kind, e.Store.GetListID(), e.DPG)
		}
	}
}

// Every issuer DPG must get BOTH kinds. Pre-auth issues SD-JWT (token) and
// auth-code issues ldp_vc (bitstring); a DPG missing a kind silently loses
// revocability for whatever it issues in that format.
func TestWireStatusListSet_EveryIssuerDPGGetsBothKinds(t *testing.T) {
	h := wireForTest(t, issuerOnlyAdapter{dpgs: injiOnlyDPGs()})

	for dpg := range injiOnlyDPGs() {
		for _, kind := range []string{"bitstring", "token"} {
			e := h.StatusLists.For(dpg, kind)
			if e == nil {
				t.Errorf("DPG %q kind %q: no list", dpg, kind)
				continue
			}
			if e.DPG != dpg {
				t.Errorf("DPG %q kind %q resolved to %q's list — DPGs are not isolated",
					dpg, kind, e.DPG)
			}
			if e.Signer == nil {
				t.Errorf("DPG %q kind %q: no signer", dpg, kind)
			}
		}
	}
}

// Decoupled means decoupled: no two DPGs may share a signing identity, or
// one DPG's key would vouch for another's list. (Within a single DPG,
// sharing a key across its two lists would be harmless — the constraint is
// across DPGs.)
func TestWireStatusListSet_IssuersAreDistinctAcrossDPGs(t *testing.T) {
	h := wireForTest(t, issuerOnlyAdapter{dpgs: injiOnlyDPGs()})

	owner := map[string]string{} // iss -> DPG that claimed it
	for _, e := range h.StatusLists.Entries() {
		if e.Signer == nil {
			continue
		}
		iss := e.Signer.Issuer()
		if prev, seen := owner[iss]; seen && prev != e.DPG {
			t.Errorf("DPGs %q and %q share signing identity %s", prev, e.DPG, iss)
		}
		owner[iss] = e.DPG
	}
}

// Credentials issued before per-DPG lists point their credentialStatus at
// /status-list/{kind}/v1 and cannot be rewritten. Those URLs must keep
// resolving, and both kinds must survive — they share the id "v1", so an
// id-only index drops one of them.
func TestWireStatusListSet_LegacyV1ListsStayResolvable(t *testing.T) {
	h := wireForTest(t, issuerOnlyAdapter{dpgs: injiOnlyDPGs()})

	for _, kind := range []string{"bitstring", "token"} {
		e := h.StatusLists.ByID(kind, "v1")
		if e == nil {
			t.Fatalf("legacy %q list v1 no longer resolves — already-issued credentials break", kind)
		}
		if e.Kind != kind {
			t.Errorf("ByID(%q,\"v1\") returned a %q list", kind, e.Kind)
		}
		if e.Signer == nil {
			t.Errorf("legacy %q list v1 has no signer", kind)
		}
	}
}

// A deployment with no issuer DPGs, or one whose adapter can't answer at
// boot, must still end up with working signed default lists — degrading to
// "no revocation at all" is exactly the outcome this change exists to stop.
func TestWireStatusListSet_KeepsSignedDefaultsWithoutDPGs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		adapter backend.Adapter
	}{
		{"no issuer DPGs", noDpgAdapter{}},
		{"adapter cannot answer", erroringAdapter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := wireForTest(t, tc.adapter)
			for _, kind := range []string{"bitstring", "token"} {
				e := h.StatusLists.For("", kind)
				if e == nil || e.Store == nil {
					t.Fatalf("no default %q list", kind)
				}
				if e.Signer == nil {
					t.Errorf("default %q list has no signer", kind)
				}
			}
		})
	}
}

// The publish URL baked into every issued credential must match the list the
// same DPG later allocates from and revokes in. If these drift, credentials
// point at a list whose bits nobody sets.
func TestWireStatusListSet_PublishURLMatchesListID(t *testing.T) {
	h := wireForTest(t, issuerOnlyAdapter{dpgs: injiOnlyDPGs()})

	for _, e := range h.StatusLists.Entries() {
		want := "https://x.test/status-list/" + e.Kind + "/" + e.Store.GetListID()
		if got := e.Store.GetPublishURL(); got != want {
			t.Errorf("list %q: publish URL %q, want %q", e.Store.GetListID(), got, want)
		}
	}
}
