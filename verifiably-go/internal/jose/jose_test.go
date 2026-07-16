package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
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

// Callers must be able to tell "checked it, and it's WRONG" apart from
// "couldn't check it" — the first has to fail closed, the second may fail
// open. That distinction has to be carried by a sentinel matched with
// errors.Is, never by the error text.
//
// Regression: statuslistcache decided fatal-vs-skip by testing the message
// for "signature invalid", which this error never contained. Every tampered
// did:jwk status list was therefore warned-and-skipped, i.e. revocation was
// trusted on faith. Returning a plain fmt.Errorf here again would silently
// reopen that hole, so pin the sentinel identity.
func TestVerifyES256_MismatchIsSentinelNotMessage(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingInput := []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1In0")
	sum := sha256.Sum256(signingInput)
	r, s, _ := ecdsa.Sign(rand.Reader, key, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	tampered := make([]byte, 64)
	copy(tampered, sig)
	tampered[0] ^= 0xFF

	// A real mismatch IS the sentinel.
	err := VerifyES256(&key.PublicKey, signingInput, tampered)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a signature mismatch must match ErrSignatureInvalid via errors.Is; got %#v", err)
	}
	// Verifying against the wrong key is also a mismatch, not a can't-check.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyES256(&other.PublicKey, signingInput, sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong-key must match ErrSignatureInvalid; got %#v", err)
	}

	// A malformed signature is NOT a mismatch: we never got to check it.
	// Conflating the two would make callers fail closed on garbage they
	// could not evaluate.
	if err := VerifyES256(&key.PublicKey, signingInput, sig[:63]); err == nil {
		t.Fatal("short signature must error")
	} else if errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("a malformed signature must not report as a mismatch; got %v", err)
	}

	// Wrapping must preserve errors.Is — callers wrap for context.
	wrapped := errors.New("outer: " + ErrSignatureInvalid.Error())
	if errors.Is(wrapped, ErrSignatureInvalid) {
		t.Error("string-equal errors must NOT satisfy errors.Is — that would be message matching again")
	}
	if !strings.Contains(ErrSignatureInvalid.Error(), "signature") {
		t.Error("sentinel message should still mention signature for logs")
	}
}
