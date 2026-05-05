package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// genKey produces a fresh P-256 SigningKey for tests so each test is
// independent of any walt.id state.
func genKey(t *testing.T) *SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return &SigningKey{priv: priv, kid: "test-kid", iss: "did:test:issuer"}
}

func TestBitstringSetGet(t *testing.T) {
	b := New(64)
	if b.Get(0) {
		t.Fatal("fresh bit must be 0")
	}
	if err := b.Set(0, true); err != nil {
		t.Fatal(err)
	}
	if !b.Get(0) {
		t.Fatal("Set then Get should be true")
	}
	if err := b.Set(0, false); err != nil {
		t.Fatal(err)
	}
	if b.Get(0) {
		t.Fatal("after clearing, Get should be false")
	}
	if err := b.Set(64, true); err == nil {
		t.Fatal("Set out of range should error")
	}
}

func TestBitstringMSBFirst(t *testing.T) {
	// W3C BSL 2023 §5.1 / IETF Token Status List both put bit 0 at
	// the MSB of byte 0. Verify bit 0 lands at 0x80, bit 7 at 0x01,
	// bit 8 at 0x80 of byte 1.
	b := New(16)
	if err := b.Set(0, true); err != nil {
		t.Fatal(err)
	}
	if got := b.Bytes()[0]; got != 0x80 {
		t.Fatalf("bit 0 in byte 0: got 0x%x, want 0x80", got)
	}
	b = New(16)
	if err := b.Set(7, true); err != nil {
		t.Fatal(err)
	}
	if got := b.Bytes()[0]; got != 0x01 {
		t.Fatalf("bit 7 in byte 0: got 0x%x, want 0x01", got)
	}
	b = New(16)
	if err := b.Set(8, true); err != nil {
		t.Fatal(err)
	}
	if got := b.Bytes()[1]; got != 0x80 {
		t.Fatalf("bit 8 in byte 1: got 0x%x, want 0x80", got)
	}
}

func TestGzipRoundTrip(t *testing.T) {
	a := New(256)
	for i := 0; i < 256; i += 17 {
		if err := a.Set(i, true); err != nil {
			t.Fatal(err)
		}
	}
	enc, err := a.EncodeGzipBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeGzipBase64URL(enc, 256)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		if a.Get(i) != b.Get(i) {
			t.Fatalf("round-trip mismatch at bit %d", i)
		}
	}
}

func TestZlibRoundTrip(t *testing.T) {
	// IETF Token Status List uses LSB-first bit ordering — both source
	// and decoded forms have to use it for the round-trip to match.
	a := NewIETF(256)
	for i := 1; i < 256; i += 13 {
		if err := a.Set(i, true); err != nil {
			t.Fatal(err)
		}
	}
	enc, err := a.EncodeZlibBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeZlibBase64URL(enc, 256)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		if a.Get(i) != b.Get(i) {
			t.Fatalf("round-trip mismatch at bit %d", i)
		}
	}
}

// TestBitstringLSBFirst pins the IETF Token Status List bit-ordering
// convention to a couple of concrete byte values so a future refactor
// can't silently flip back to MSB-first without breaking this test.
func TestBitstringLSBFirst(t *testing.T) {
	b := NewIETF(16)
	if err := b.Set(0, true); err != nil {
		t.Fatal(err)
	}
	if got := b.Bytes()[0]; got != 0x01 {
		t.Fatalf("bit 0 in byte 0 (LSB-first): got 0x%x, want 0x01", got)
	}
	b = NewIETF(16)
	if err := b.Set(7, true); err != nil {
		t.Fatal(err)
	}
	if got := b.Bytes()[0]; got != 0x80 {
		t.Fatalf("bit 7 in byte 0 (LSB-first): got 0x%x, want 0x80", got)
	}
	b = NewIETF(16)
	if err := b.Set(8, true); err != nil {
		t.Fatal(err)
	}
	if got := b.Bytes()[1]; got != 0x01 {
		t.Fatalf("bit 8 in byte 1 (LSB-first): got 0x%x, want 0x01", got)
	}
}

func TestStoreAllocateAndRevoke(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore("bitstring", "v1", filepath.Join(dir, "bs.json"), "https://example/sl/v1")
	if err != nil {
		t.Fatal(err)
	}
	idx0, err := s.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	idx1, err := s.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if idx0 != 0 || idx1 != 1 {
		t.Fatalf("indices: got %d,%d want 0,1", idx0, idx1)
	}
	if s.IsRevoked(idx1) {
		t.Fatal("freshly allocated index must not be revoked")
	}
	if err := s.Revoke(idx1); err != nil {
		t.Fatal(err)
	}
	if !s.IsRevoked(idx1) {
		t.Fatal("after revoke IsRevoked should be true")
	}
	if s.IsRevoked(idx0) {
		t.Fatal("revoking idx1 must not affect idx0")
	}
	if err := s.Reinstate(idx1); err != nil {
		t.Fatal(err)
	}
	if s.IsRevoked(idx1) {
		t.Fatal("after reinstate IsRevoked should be false")
	}
}

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bs.json")
	s1, err := NewStore("bitstring", "v1", path, "")
	if err != nil {
		t.Fatal(err)
	}
	idx, _ := s1.Allocate()
	if err := s1.Revoke(idx); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore("bitstring", "v1", path, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s2.IsRevoked(idx) {
		t.Fatal("revocation should persist across reload")
	}
	if s2.NextFree() != s1.NextFree() {
		t.Fatalf("nextFree drift: %d vs %d", s2.NextFree(), s1.NextFree())
	}
}

func TestPublishBitstringJWT(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore("bitstring", "v1", filepath.Join(dir, "bs.json"), "https://issuer/sl/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	idx, _ := s.Allocate()
	_ = s.Revoke(idx)
	key := genKey(t)
	jwt, err := s.PublishBitstringJWT(key)
	if err != nil {
		t.Fatalf("PublishBitstringJWT: %v", err)
	}
	if strings.Count(jwt, ".") != 2 {
		t.Fatalf("JWT must have 3 parts, got %q", jwt)
	}
	payload, err := key.VerifyES256(jwt)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var p struct {
		VC map[string]any `json:"vc"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	cs, ok := p.VC["credentialSubject"].(map[string]any)
	if !ok {
		t.Fatalf("credentialSubject missing: %+v", p.VC)
	}
	encoded, _ := cs["encodedList"].(string)
	if encoded == "" {
		t.Fatal("encodedList missing")
	}
	bs, err := DecodeGzipBase64URL(encoded, s.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !bs.Get(idx) {
		t.Fatalf("decoded bitstring should show bit %d as revoked", idx)
	}
}

func TestPublishTokenStatusList(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore("token", "v1", filepath.Join(dir, "tk.json"), "https://issuer/sl/token/v1")
	if err != nil {
		t.Fatal(err)
	}
	idx, _ := s.Allocate()
	_ = s.Revoke(idx)
	key := genKey(t)
	jwt, err := s.PublishTokenStatusList(key)
	if err != nil {
		t.Fatalf("PublishTokenStatusList: %v", err)
	}
	payload, err := key.VerifyES256(jwt)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var p struct {
		StatusList map[string]any `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.StatusList["bits"].(float64); got != 1 {
		t.Fatalf("bits: got %v want 1", p.StatusList["bits"])
	}
	encoded, _ := p.StatusList["lst"].(string)
	if encoded == "" {
		t.Fatal("lst missing")
	}
	bs, err := DecodeZlibBase64URL(encoded, s.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !bs.Get(idx) {
		t.Fatalf("decoded token-list bit %d should be revoked", idx)
	}
}

// TestParseWaltidIssuerKey covers the two envelope shapes we accept.
func TestParseWaltidIssuerKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkInner := map[string]string{
		"kty": "EC", "crv": "P-256", "kid": "k1",
		"x": base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
		"d": base64.RawURLEncoding.EncodeToString(priv.D.Bytes()),
	}
	innerJSON, _ := json.Marshal(jwkInner)

	// Envelope shape: {"type":"jwk","jwk":{...}}
	envelope, _ := json.Marshal(map[string]any{"type": "jwk", "jwk": json.RawMessage(innerJSON)})
	k, err := ParseWaltidIssuerKey(envelope, "did:test:1")
	if err != nil {
		t.Fatalf("envelope parse: %v", err)
	}
	if k.kid != "k1" {
		t.Fatalf("kid: got %q want k1", k.kid)
	}

	// Bare JWK (older walt.id builds).
	if _, err := ParseWaltidIssuerKey(innerJSON, "did:test:1"); err != nil {
		t.Fatalf("bare jwk parse: %v", err)
	}

	// Round-trip sign/verify with the parsed key.
	tok, err := k.SignJWT("JWT", map[string]any{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.VerifyES256(tok); err != nil {
		t.Fatalf("sign/verify round-trip: %v", err)
	}
}
