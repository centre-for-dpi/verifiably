package statuslistcache

import (
	"context"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// The producer/consumer contract for self-signed status lists.
//
// statuslist mints the signing key and stamps its did:jwk into `iss`;
// statuslistcache resolves that `iss` back to a key and checks the
// signature. Nothing in the type system ties those two halves together, so
// this pins them: a list signed by a freshly-minted key must verify through
// the real verifier path, unchanged.
//
// This is a narrow contract, and both constraints are load-bearing:
//   - verifyJWT resolves non-did:jwk issuers through the DID resolver, which
//     only implements did:web. A did:key issuer resolves to nothing.
//   - verifyES256JWT hard-requires EC/P-256. Ed25519 is rejected outright.
//
// So the "obvious" choice — mirror LDSigner, which uses Ed25519 and did:key
// for the JSON-LD list — would produce lists that nothing can verify. If
// someone changes the key type, the curve, or the did:jwk encoding, this
// test is what catches it.
func TestSelfSignedKeyVerifiesThroughFetcher(t *testing.T) {
	key, err := statuslist.NewSelfSignedKey(t.TempDir(), "inji-certify-pre-auth-token")
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := key.SignJWT("statuslist+jwt", map[string]any{
		"iss":         key.Issuer(),
		"sub":         "https://issuer.test/status-list/token/inji-certify-pre-auth-token",
		"status_list": map[string]any{"bits": 1, "lst": "eJzswDEBAAAAwiD7pzbGHhgAAAA"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// No resolver: did:jwk must be self-contained, or a verifier would need
	// to reach the network to check a status list.
	f := &Fetcher{}
	if err := f.verifyJWT(context.Background(), jwt, ""); err != nil {
		t.Fatalf("a self-signed status list must verify through the real path: %v", err)
	}
}

// A tampered list must be REJECTED, not skipped. verifyJWT fails open on
// "couldn't check" — so if a genuine mismatch is ever misclassified as
// couldn't-check, revocation silently becomes advisory. This is the whole
// point of the jose.ErrSignatureInvalid sentinel.
func TestSelfSignedTamperedListIsRejectedNotSkipped(t *testing.T) {
	key, err := statuslist.NewSelfSignedKey(t.TempDir(), "tamper")
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := key.SignJWT("statuslist+jwt", map[string]any{"iss": key.Issuer(), "sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")

	// Corrupt the FIRST signature char, not the last: a 64-byte signature is
	// 86 base64url chars and the final char carries only 2 significant bits,
	// so changing it can decode to identical bytes and still verify.
	repl := "A"
	if strings.HasPrefix(parts[2], "A") {
		repl = "Q"
	}
	tampered := parts[0] + "." + parts[1] + "." + repl + parts[2][1:]

	f := &Fetcher{}
	if err := f.verifyJWT(context.Background(), tampered, ""); err == nil {
		t.Fatal("a tampered status list must be rejected — revocation would be trusted on faith")
	}
}

// A list signed by one DPG's key must not verify under another's `iss`.
// Because verifyJWT takes the key from the token's own `iss`, a swapped
// issuer must fail the signature check rather than quietly pass.
func TestSelfSignedListDoesNotVerifyUnderAnotherDPGsIssuer(t *testing.T) {
	dir := t.TempDir()
	preauth, err := statuslist.NewSelfSignedKey(dir, "pre-auth-token")
	if err != nil {
		t.Fatal(err)
	}
	authcode, err := statuslist.NewSelfSignedKey(dir, "auth-code-token")
	if err != nil {
		t.Fatal(err)
	}
	if preauth.Issuer() == authcode.Issuer() {
		t.Fatal("precondition: DPG keys must differ")
	}

	// Signed by pre-auth, but claiming to be auth-code.
	jwt, err := preauth.SignJWT("statuslist+jwt", map[string]any{"iss": authcode.Issuer(), "sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{}
	if err := f.verifyJWT(context.Background(), jwt, ""); err == nil {
		t.Fatal("one DPG's key must not be able to sign a list attributed to another")
	}
}
