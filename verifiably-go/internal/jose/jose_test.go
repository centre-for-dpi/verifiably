package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestDecodeBase64URLBigInt(t *testing.T) {
	want := big.NewInt(65537)
	raw := want.Bytes()

	// Unpadded base64url (the RFC 7515 form).
	if got, err := DecodeBase64URLBigInt(base64.RawURLEncoding.EncodeToString(raw)); err != nil || got.Cmp(want) != 0 {
		t.Errorf("unpadded: got %v err %v, want %v", got, err, want)
	}
	// Padded base64url (some issuers emit it; must still decode).
	if got, err := DecodeBase64URLBigInt(base64.URLEncoding.EncodeToString(raw)); err != nil || got.Cmp(want) != 0 {
		t.Errorf("padded: got %v err %v, want %v", got, err, want)
	}
	// Garbage → error.
	if _, err := DecodeBase64URLBigInt("!!!not base64!!!"); err == nil {
		t.Error("expected error on invalid base64")
	}
}

func TestVerifyES256_RoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingInput := []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1In0")
	sum := sha256.Sum256(signingInput)
	r, s, _ := ecdsa.Sign(rand.Reader, key, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	if err := VerifyES256(&key.PublicKey, signingInput, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Tamper a byte → must fail.
	bad := make([]byte, 64)
	copy(bad, sig)
	bad[0] ^= 0xFF
	if err := VerifyES256(&key.PublicKey, signingInput, bad); err == nil {
		t.Error("tampered signature accepted")
	}

	// Wrong length → must fail.
	if err := VerifyES256(&key.PublicKey, signingInput, sig[:63]); err == nil {
		t.Error("short signature accepted")
	}

	// Wrong key → must fail.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyES256(&other.PublicKey, signingInput, sig); err == nil {
		t.Error("signature verified against wrong key")
	}
}
