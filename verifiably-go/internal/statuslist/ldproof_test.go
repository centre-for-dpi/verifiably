package statuslist

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestBase58RoundTrip(t *testing.T) {
	cases := [][]byte{
		{0}, {0, 0, 1, 2, 3}, {255, 254, 253}, []byte("hello world"),
		make([]byte, 32), // all-zero 32-byte seed
	}
	for i, in := range cases {
		enc := base58Encode(in)
		dec, err := decodeSeed(enc)
		if err != nil {
			t.Fatalf("case %d decode %q: %v", i, enc, err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("case %d round-trip: got %v want %v (enc %q)", i, dec, in, enc)
		}
	}
	if _, err := decodeSeed("0OIl"); err == nil {
		t.Fatal("decodeSeed accepted non-base58 chars")
	}
}

func TestLDSignerPersistenceAndDID(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewLDSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s1.DID(), "did:key:z6Mk") {
		t.Fatalf("did:key format: %s", s1.DID())
	}
	s2, err := NewLDSigner(dir) // reload same state dir
	if err != nil {
		t.Fatal(err)
	}
	if s2.DID() != s1.DID() {
		t.Fatalf("persistence: %s != %s", s2.DID(), s1.DID())
	}
}

// TestLDSignerSignVerifies signs a sample BitstringStatusListCredential and
// verifies the Ed25519Signature2020 proof exactly as an external verifier would
// (canonicalize proof config + document offline via the bundled contexts, SHA-256
// each, concat proof||doc, ed25519.Verify against the did:key public key). MOSIP
// Inji Verify accepting this live confirms the on-wire compatibility.
func TestLDSignerSignVerifies(t *testing.T) {
	s, err := NewLDSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vc := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		"id":        "https://verifiably.example/status-list/bitstring/v1",
		"type":      []any{"VerifiableCredential", "BitstringStatusListCredential"},
		"issuer":    s.DID(),
		"validFrom": "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{
			"id":            "https://verifiably.example/status-list/bitstring/v1#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "uH4sIAAAAAAAAA-3AMQEAAAACIP1_2hkwoAAAAAAAAAAAAAAAAAAAAOBthtEUAAAAAAA",
		},
	}
	signed, err := s.Sign(vc)
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := signed["proof"].(map[string]any)
	if !ok {
		t.Fatalf("no proof in signed VC: %+v", signed)
	}
	if proof["type"] != "Ed25519Signature2020" || proof["proofPurpose"] != "assertionMethod" {
		t.Fatalf("proof metadata: %+v", proof)
	}
	pv, _ := proof["proofValue"].(string)
	if !strings.HasPrefix(pv, "z") {
		t.Fatalf("proofValue not multibase-z: %q", pv)
	}

	// Reconstruct the signing input and verify against the did:key public key.
	pub := ed25519PubFromDIDKey(t, s.DID())
	proofConfig := map[string]any{
		"@context":           vc["@context"],
		"type":               "Ed25519Signature2020",
		"created":            proof["created"],
		"verificationMethod": proof["verificationMethod"],
		"proofPurpose":       "assertionMethod",
	}
	canonProof, err := s.canonicalize(proofConfig)
	if err != nil {
		t.Fatalf("canon proof: %v", err)
	}
	doc := map[string]any{}
	for k, v := range vc {
		doc[k] = v
	}
	canonDoc, err := s.canonicalize(doc)
	if err != nil {
		t.Fatalf("canon doc: %v", err)
	}
	ph := sha256.Sum256([]byte(canonProof))
	dh := sha256.Sum256([]byte(canonDoc))
	sig, err := decodeSeed(strings.TrimPrefix(pv, "z"))
	if err != nil {
		t.Fatalf("decode proofValue: %v", err)
	}
	if !ed25519.Verify(pub, append(ph[:], dh[:]...), sig) {
		t.Fatal("Ed25519Signature2020 proof does not verify")
	}
}

func ed25519PubFromDIDKey(t *testing.T, did string) ed25519.PublicKey {
	t.Helper()
	raw, err := decodeSeed(strings.TrimPrefix(strings.TrimPrefix(did, "did:key:"), "z"))
	if err != nil {
		t.Fatalf("decode did:key: %v", err)
	}
	if len(raw) != 2+ed25519.PublicKeySize || raw[0] != 0xed || raw[1] != 0x01 {
		t.Fatalf("did:key multicodec: %x", raw[:2])
	}
	return ed25519.PublicKey(raw[2:])
}
