package handlers

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/verifiably/verifiably-go/internal/delegation"
	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// encodedListWithBit builds a W3C BSL `encodedList` (multibase 'u' + gzip +
// base64url) with exactly one bit set — the shape Inji's auth-code Certify
// serves inside credentialSubject.encodedList.
func encodedListWithBit(t *testing.T, idx int) string {
	t.Helper()
	bs := statuslist.New(statuslist.DefaultBits)
	if err := bs.Set(idx, true); err != nil {
		t.Fatal(err)
	}
	enc, err := bs.EncodeGzipBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	return "u" + enc // multibase base64url prefix, as W3C + Certify emit
}

// F(2): the auth-code W3C credential's status list is served by Certify as a
// BARE JSON-LD BitstringStatusListCredential (application/json), not a compact
// JWS. statusBitRevoked must read credentialSubject.encodedList straight off the
// top-level VC instead of splitting the JSON on '.' as if it were a JWT (which
// decoded a chunk into binary → the "invalid character ''" 0x8a failure).
func TestStatusBitRevoked_BareJSONLD(t *testing.T) {
	const revIdx = 11711
	statusVC := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential", "BitstringStatusListCredential"},
		"issuer":   "did:web:inji-certify-authcode.in-labs.cdpi.dev",
		"credentialSubject": map[string]any{
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   encodedListWithBit(t, revIdx),
		},
		"proof": map[string]any{"type": "Ed25519Signature2020"},
	}
	raw, _ := json.Marshal(statusVC)

	revoked, err := statusBitRevoked(string(raw), delegation.StatusRef{Type: "BitstringStatusListEntry", Index: revIdx})
	if err != nil {
		t.Fatalf("bare JSON-LD status list must parse, got error: %v", err)
	}
	if !revoked {
		t.Errorf("index %d should read revoked from the JSON-LD list", revIdx)
	}
	clear, err := statusBitRevoked(string(raw), delegation.StatusRef{Type: "BitstringStatusListEntry", Index: 42})
	if err != nil {
		t.Fatalf("clear index parse error: %v", err)
	}
	if clear {
		t.Errorf("index 42 should read not-revoked")
	}
}

// Regression: a status list served as a compact JWS (our own status server's
// application/vc+jwt form — payload has the VC nested under "vc") still decodes.
func TestStatusBitRevoked_CompactJWS(t *testing.T) {
	const revIdx = 7
	payload := map[string]any{
		"vc": map[string]any{
			"credentialSubject": map[string]any{"encodedList": encodedListWithBit(t, revIdx)},
		},
	}
	pj, _ := json.Marshal(payload)
	jws := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(pj) + ".sig"

	revoked, err := statusBitRevoked(jws, delegation.StatusRef{Type: "BitstringStatusListEntry", Index: revIdx})
	if err != nil {
		t.Fatalf("compact JWS status list parse error: %v", err)
	}
	if !revoked {
		t.Errorf("index %d should read revoked from the JWS list", revIdx)
	}
}

// statusListClaims accepts both a bare JSON object and a compact JWS.
func TestStatusListClaims_BothForms(t *testing.T) {
	m, err := statusListClaims(`  {"credentialSubject":{"encodedList":"uX"}}`)
	if err != nil || m["credentialSubject"] == nil {
		t.Fatalf("bare JSON form: %v (%v)", m, err)
	}
	jws := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"foo":"bar"}`)) + ".sig"
	m2, err := statusListClaims(jws)
	if err != nil || m2["foo"] != "bar" {
		t.Fatalf("JWS form: %v (%v)", m2, err)
	}
}
