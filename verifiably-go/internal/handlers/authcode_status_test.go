package handlers

import (
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// Part B (corrected): on the auth-code (Certify) path verifiably OWNS revocation
// only for SD-JWT — Certify never ledgers SD-JWT, so its TokenStore is that
// credential's sole status list. W3C ldp_vc is Certify-NATIVE (the credentialStatus
// block makes Certify manage its own bitstring list + ledger the credential), so
// statusStoreFor must return nil for W3C even when a BitstringStore is configured —
// preventing verifiably from allocating a disconnected parallel slot and hijacking
// the revoke to a list the issued VC never references.
func TestStatusStoreFor_CertifyNativeW3C(t *testing.T) {
	dir := t.TempDir()
	bs, err := statuslist.NewStore("bitstring", "v1", dir+"/bs.json", "https://x/status-list/bitstring/v1")
	if err != nil {
		t.Fatalf("new bitstring store: %v", err)
	}
	tk, err := statuslist.NewStore("token", "v1", dir+"/tk.json", "https://x/status-list/token/v1")
	if err != nil {
		t.Fatalf("new token store: %v", err)
	}
	h := &H{TokenStore: tk, BitstringStore: bs}

	if got := h.statusStoreFor(authcodeVendor, "sd_jwt_vc (IETF)"); got != statuslist.Backend(tk) {
		t.Errorf("SD-JWT statusStoreFor = %v, want the TokenStore (verifiably-owned)", got)
	}
	for _, std := range []string{"w3c_vcdm_2", "w3c_vcdm_1"} {
		if got := h.statusStoreFor(authcodeVendor, std); got != nil {
			t.Errorf("%s statusStoreFor = %T, want nil (Certify-native — no verifiably slot)", std, got)
		}
	}
}

// Each issuer DPG must allocate from its OWN list: revoking a credential
// issued by one DPG must not flip a bit in another's. Before per-DPG lists
// there was a single list per kind, so every issuer shared one bitmap.
func TestStatusStoreFor_PerDPGIsolation(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) statuslist.Backend {
		s, err := statuslist.NewStore("token", name, dir+"/"+name+".json", "https://x/status-list/token/"+name)
		if err != nil {
			t.Fatalf("new store %s: %v", name, err)
		}
		return s
	}
	a, b := mk("dpg-a-token"), mk("dpg-b-token")
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: a, DPG: "DPG A", Kind: "token"})
	set.Register(&StatusListEntry{Store: b, DPG: "DPG B", Kind: "token"})
	h := &H{StatusLists: set}

	if got := h.statusStoreFor("DPG A", "sd_jwt_vc (IETF)"); got != a {
		t.Errorf("DPG A resolved to %v, want its own list", got)
	}
	if got := h.statusStoreFor("DPG B", "sd_jwt_vc (IETF)"); got != b {
		t.Errorf("DPG B resolved to %v, want its own list", got)
	}

	// Revoking in A's list must leave B's untouched.
	idx, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Allocate(); err != nil {
		t.Fatal(err)
	}
	if err := a.Revoke(idx); err != nil {
		t.Fatal(err)
	}
	if !a.IsRevoked(idx) {
		t.Error("DPG A index must be revoked in its own list")
	}
	if b.IsRevoked(idx) {
		t.Error("revoking in DPG A's list must not revoke the same index in DPG B's")
	}
}

// Part B: the auth-code extraction view must emit the computed statusIdx (per
// holder, from statusIdx_<slug>) + statusUri (the constant list URL) columns for
// W3C too, so the credentialStatus block's ${statusUri}/${statusIdx} resolve.
func TestAuthcodeViewDDL_StatusColumns(t *testing.T) {
	ddl := authcodeViewDDL("idw3c", []string{"givenName"}, true, "https://verifiably.example/status-list/bitstring/v1")
	for _, want := range []string{
		`AS "statusIdx"`,
		`AS "statusUri"`,
		"statusIdx_idw3c",
		"https://verifiably.example/status-list/bitstring/v1",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("view DDL missing %q\n%s", want, ddl)
		}
	}

	// Statusless: no computed status columns.
	plain := authcodeViewDDL("plain", []string{"givenName"}, false, "")
	if strings.Contains(plain, `AS "statusIdx"`) || strings.Contains(plain, `AS "statusUri"`) {
		t.Errorf("statusless view must not add status columns\n%s", plain)
	}
}
