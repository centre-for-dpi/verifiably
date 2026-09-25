// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// walletCaps lists the wallet features and the choices of the stack.
func walletKeysDeployment(features ...backendv1.Feature) func(*testing.T) *harness {
	return func(t *testing.T) *harness {
		topo := holderDeployment(features...)
		snap := topo.Snapshot(t.Context())
		snap.Peers[0].Capabilities.WalletKeyTypes = []string{"Ed25519", "secp256r1", "secp256k1", "RSA"}
		snap.Peers[0].Capabilities.WalletDidMethods = []string{"did:key", "did:jwk", "did:cheqd"}
		return setupShell(t, nil, topo)
	}
}

// TestListKeysAndDids draws the keys and the DIDs of the stack wallet,
// with the default DID, and makes a key, a DID, and a new default.
func TestListKeysAndDids(t *testing.T) {
	h := walletKeysDeployment(backendv1.Feature_FEATURE_WALLET_KEYS, backendv1.Feature_FEATURE_WALLET_DIDS, backendv1.Feature_FEATURE_WALLET_EVENTS)(t)
	rec := h.get(t, "/wallet/keys")
	if rec.Code != http.StatusOK {
		t.Fatalf("keys: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"v1sbluyFJrMT6Lt46S4N_CBH1g7OWHpm_f3uK93dSLE", "Travel", "secp256r1",
		"did:key:z6MkjoRhq1jSNJdLiruSXrFFxagqrztZaXHqHGUTKJbcNywp", "Onboarding", "Default",
		`action="/wallet/keys/default"`, `value="did:jwk:eyJrdHkiOiJFQyJ9"`,
		`action="/wallet/keys/key"`, `<option value="secp256k1">secp256k1</option>`,
		`action="/wallet/keys/did"`, `<option value="did:cheqd">did:cheqd</option>`,
		"Ministry of Transport", "Receive",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the keys page lacks %q", want)
		}
	}
	if rec := h.post(t, "/wallet/keys/key", url.Values{"key_type": {"secp256k1"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("make a key: %d %s", rec.Code, rec.Body.String())
	}
	if len(h.holder.madeKeys) != 1 || h.holder.madeKeys[0].GetKeyType() != "secp256k1" || h.holder.madeKeys[0].GetWalletId() != "wallet-1" {
		t.Errorf("keys made %+v", h.holder.madeKeys)
	}
	if rec := h.post(t, "/wallet/keys/did", url.Values{"method": {"did:jwk"}, "key_id": {"_nd-T2YRYLSmuKkJZlRI641zrCIJLTpiHeqMwXuvdug"}, "alias": {"Work"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("make a DID: %d", rec.Code)
	}
	if len(h.holder.madeDids) != 1 || h.holder.madeDids[0].GetMethod() != "did:jwk" || h.holder.madeDids[0].GetAlias() != "Work" {
		t.Errorf("DIDs made %+v", h.holder.madeDids)
	}
	if rec := h.post(t, "/wallet/keys/default", url.Values{"did": {"did:jwk:eyJrdHkiOiJFQyJ9"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("default: %d", rec.Code)
	}
	if h.holder.defaultDid != "did:jwk:eyJrdHkiOiJFQyJ9" {
		t.Errorf("default = %q", h.holder.defaultDid)
	}
	// A choice the stack does not list is refused before any call.
	if rec := h.post(t, "/wallet/keys/key", url.Values{"key_type": {"P-521"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown key type: %d", rec.Code)
	}
	if rec := h.post(t, "/wallet/keys/did", url.Values{"method": {"did:web"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown method: %d", rec.Code)
	}
	if rec := h.post(t, "/wallet/keys/default", url.Values{}); rec.Code != http.StatusBadRequest {
		t.Errorf("no DID: %d", rec.Code)
	}
}

// TestKeysPageOnlyWithFeature shows each part of the page only when the
// adapter lists its feature, and answers 404 for the forms otherwise.
func TestKeysPageOnlyWithFeature(t *testing.T) {
	h := walletKeysDeployment(backendv1.Feature_FEATURE_WALLET_KEYS)(t)
	body := h.get(t, "/wallet/keys").Body.String()
	if strings.Contains(body, `action="/wallet/keys/did"`) || strings.Contains(body, "Ministry of Transport") {
		t.Error("the page shows DIDs or events the stack does not list")
	}
	if rec := h.post(t, "/wallet/keys/did", url.Values{"method": {"did:jwk"}}); rec.Code != http.StatusNotFound {
		t.Errorf("a DID without the feature: %d", rec.Code)
	}
	if rec := h.post(t, "/wallet/keys/default", url.Values{"did": {"did:x"}}); rec.Code != http.StatusNotFound {
		t.Errorf("a default without the feature: %d", rec.Code)
	}
	none := setupShell(t, nil, holderDeployment())
	if rec := none.post(t, "/wallet/keys/key", url.Values{"key_type": {"Ed25519"}}); rec.Code != http.StatusNotFound {
		t.Errorf("a key without the feature: %d", rec.Code)
	}
	// A failed read shows a problem, not a broken page.
	failing := walletKeysDeployment(backendv1.Feature_FEATURE_WALLET_KEYS)(t)
	failing.holder.keysErr = errDown
	rec := failing.get(t, "/wallet/keys")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "did not answer") {
		t.Errorf("a failed read: %d %s", rec.Code, rec.Body.String())
	}
}

// errDown is the failure of a stack that does not answer.
var errDown = errors.New("the stack is down")
