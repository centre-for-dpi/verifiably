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

	if got := h.statusStoreFor("sd_jwt_vc (IETF)"); got != statuslist.Backend(tk) {
		t.Errorf("SD-JWT statusStoreFor = %v, want the TokenStore (verifiably-owned)", got)
	}
	for _, std := range []string{"w3c_vcdm_2", "w3c_vcdm_1"} {
		if got := h.statusStoreFor(std); got != nil {
			t.Errorf("%s statusStoreFor = %T, want nil (Certify-native — no verifiably slot)", std, got)
		}
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
