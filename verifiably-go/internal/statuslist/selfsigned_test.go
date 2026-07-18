package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/jose"
)

// verifyWithCoords rebuilds the public key from did:jwk x/y and verifies the
// compact JWS exactly as statuslistcache.verifyES256JWT does.
func verifyWithCoords(t *testing.T, parts []string, xStr, yStr string) error {
	t.Helper()
	x, err := jose.DecodeBase64URLBigInt(xStr)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	y, err := jose.DecodeBase64URLBigInt(yStr)
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return jose.VerifyES256(&pub, []byte(parts[0]+"."+parts[1]), sig)
}

// corruptSig returns s with its FIRST base64url char changed, keeping the
// signature well-formed and the same length. It must be the first char, not
// the last: a 64-byte sig is 86 base64url chars and the final char carries
// only 2 significant bits (the low 4 are padding), so 'A'->'B' there decodes
// to identical bytes and would still verify.
func corruptSig(s string) string {
	if s == "" {
		return s
	}
	repl := byte('A')
	if s[0] == 'A' {
		repl = 'Q' // 'A'=000000, 'Q'=010000 — differs in a significant bit
	}
	return string(repl) + s[1:]
}

// The did:jwk a self-managed key advertises must decode back to the exact
// public key that signed, or the verifier can't check the list. This is the
// contract the whole self-signed scheme rests on, so pin both halves.
func TestNewSelfSignedKeyDIDJWKRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, err := NewSelfSignedKey(dir, "inji-preauth")
	if err != nil {
		t.Fatalf("NewSelfSignedKey: %v", err)
	}
	iss := key.Issuer()
	if !strings.HasPrefix(iss, "did:jwk:") {
		t.Fatalf("iss must be a did:jwk, got %q", iss)
	}

	// Decode the did:jwk the same way statuslistcache.decodeDIDJWK does.
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(iss, "did:jwk:"))
	if err != nil {
		t.Fatalf("did:jwk payload must be raw-base64url: %v", err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatalf("did:jwk payload must be JSON: %v", err)
	}
	// verifyES256JWT rejects anything that isn't EC/P-256 outright.
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		t.Fatalf("did:jwk must be EC/P-256, got kty=%v crv=%v", jwk["kty"], jwk["crv"])
	}
	if _, ok := jwk["d"]; ok {
		t.Fatal("did:jwk must not leak the private component d")
	}
	// Coordinates are fixed-length for P-256; a short field breaks verifiers.
	for _, f := range []string{"x", "y"} {
		s, _ := jwk[f].(string)
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("%s must be raw-base64url: %v", f, err)
		}
		if len(b) != 32 {
			t.Fatalf("%s must be 32 bytes, got %d", f, len(b))
		}
	}

	// The advertised key must actually verify what this key signs.
	jwt, err := key.SignJWT("statuslist+jwt", map[string]any{"iss": iss, "sub": "https://example.test/l"})
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d parts", len(parts))
	}
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	if err := verifyWithCoords(t, parts, x, y); err != nil {
		t.Fatalf("did:jwk key must verify its own signature: %v", err)
	}

	// Tampering must not verify — otherwise the check is decorative.
	bad := append(append([]string{}, parts[:2]...), corruptSig(parts[2]))
	if err := verifyWithCoords(t, bad, x, y); err == nil {
		t.Fatal("tampered signature must not verify")
	}
}

// The key must be stable across reloads: a new did:jwk on every restart
// would orphan every list already published under the old issuer.
func TestSelfSignedKeyPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	first, err := NewSelfSignedKey(dir, "inji-authcode")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := NewSelfSignedKey(dir, "inji-authcode")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Issuer() != second.Issuer() {
		t.Fatalf("issuer must be stable across reloads:\n first=%s\nsecond=%s", first.Issuer(), second.Issuer())
	}
}

// Each DPG must get a distinct issuer, or per-DPG lists aren't decoupled.
func TestSelfSignedKeysAreDistinctPerDPG(t *testing.T) {
	dir := t.TempDir()
	a, err := NewSelfSignedKey(dir, "inji-preauth")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSelfSignedKey(dir, "waltid")
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer() == b.Issuer() {
		t.Fatal("distinct DPGs must not share a status-list issuer")
	}
}
