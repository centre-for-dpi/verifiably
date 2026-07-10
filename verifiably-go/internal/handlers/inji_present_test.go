package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// discl builds a base64url([salt, name, value]) SD-JWT disclosure.
func discl(name, value string) string {
	b, _ := json.Marshal([]any{"salt-" + name, name, value})
	return base64.RawURLEncoding.EncodeToString(b)
}

// sampleSDJWT builds a synthetic compact SD-JWT: issuer JWT (vct in payload) +
// two disclosures + trailing ~. The issuer sig need not verify — these helpers
// only parse structure.
func sampleSDJWT(t *testing.T) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"vc+sd-jwt"}`))
	pl, _ := json.Marshal(map[string]any{
		"vct": "https://verifiably.in-labs.cdpi.dev/credentials/custom-abc",
		"_sd": []string{"x", "y"},
	})
	issuer := hdr + "." + base64.RawURLEncoding.EncodeToString(pl) + ".AAAA"
	return issuer + "~" + discl("last_name", "Ndegwa") + "~" + discl("testa_id", "33764103") + "~"
}

func TestInjiSDJWTVct(t *testing.T) {
	if got := injiSDJWTVct(sampleSDJWT(t)); got != "https://verifiably.in-labs.cdpi.dev/credentials/custom-abc" {
		t.Errorf("vct = %q", got)
	}
	if got := injiSDJWTVct("not-a-jwt"); got != "" {
		t.Errorf("malformed vct = %q, want empty", got)
	}
	// valid JWT shape but no vct claim in the payload
	noVct := "aGRy." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`)) + ".sig~"
	if got := injiSDJWTVct(noVct); got != "" {
		t.Errorf("no-vct payload = %q, want empty", got)
	}
	// non-JSON payload segment
	badJSON := "aGRy." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig~"
	if got := injiSDJWTVct(badJSON); got != "" {
		t.Errorf("non-json payload = %q, want empty", got)
	}
}

func TestInjiSDJWTDisclosureFields(t *testing.T) {
	got := injiSDJWTDisclosureFields(sampleSDJWT(t))
	want := map[string]bool{"last_name": true, "testa_id": true}
	if len(got) != 2 {
		t.Fatalf("fields = %v, want 2", got)
	}
	for _, f := range got {
		if !want[f] {
			t.Errorf("unexpected field %q", f)
		}
	}
	// non-base64 and non-3-element disclosures are skipped; KB-JWT (2 dots) skipped
	notArr := base64.RawURLEncoding.EncodeToString([]byte(`{"x":1}`))
	mixed := "hdr.pl.sig~" + notArr + "~!!!notb64!!!~aaa.bbb.ccc~"
	if got := injiSDJWTDisclosureFields(mixed); len(got) != 0 {
		t.Errorf("expected 0 fields from non-disclosure parts, got %v", got)
	}
}

func TestMarshalParseECKeyPEMRoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, err := marshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseECKeyPEM(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	if got.D.Cmp(key.D) != 0 {
		t.Fatal("round-tripped key differs")
	}
	if _, err := parseECKeyPEM("not pem"); err == nil {
		t.Error("parseECKeyPEM accepted non-PEM")
	}
}

// TestInjiBuildVPToken verifies the vp_token assembly end to end: an existing
// KB-JWT is stripped, the presentation is issuer + disclosures + trailing ~, the
// sd_hash is SHA-256 of that presentation, and the fresh KB-JWT carries the
// verifier nonce/aud and verifies under the holder key.
func TestInjiBuildVPToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	base := sampleSDJWT(t)
	// Append a stale KB-JWT (3-part) that must be dropped.
	staleKB := "aGRy.cGF5.c2ln"
	compact := base + staleKB

	vp, err := injiBuildVPToken(compact, key, "nonce-123", "did:web:verifier")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(vp, "~")
	kb := parts[len(parts)-1]
	presentation := strings.TrimSuffix(vp, kb)

	// presentation = the sample's issuer + 2 disclosures + trailing ~ (stale KB gone)
	if presentation != base {
		t.Fatalf("presentation = %q\nwant           %q", presentation, base)
	}
	if kb == staleKB {
		t.Fatal("stale KB-JWT was not replaced")
	}

	// KB-JWT header/payload
	kbSegs := strings.Split(kb, ".")
	if len(kbSegs) != 3 {
		t.Fatalf("KB-JWT has %d segments", len(kbSegs))
	}
	var hdr map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(kbSegs[0])
	_ = json.Unmarshal(hb, &hdr)
	if hdr["typ"] != "kb+jwt" || hdr["alg"] != "ES256" {
		t.Fatalf("KB-JWT header = %v", hdr)
	}
	var pl map[string]any
	pb, _ := base64.RawURLEncoding.DecodeString(kbSegs[1])
	_ = json.Unmarshal(pb, &pl)
	if pl["nonce"] != "nonce-123" || pl["aud"] != "did:web:verifier" {
		t.Fatalf("KB-JWT payload nonce/aud = %v", pl)
	}
	sum := sha256.Sum256([]byte(presentation))
	wantHash := base64.RawURLEncoding.EncodeToString(sum[:])
	if pl["sd_hash"] != wantHash {
		t.Fatalf("sd_hash = %v, want %v", pl["sd_hash"], wantHash)
	}

	// signature verifies under the holder key (ES256 = r||s, 64 bytes)
	sig, _ := base64.RawURLEncoding.DecodeString(kbSegs[2])
	if len(sig) != 64 {
		t.Fatalf("sig len = %d, want 64", len(sig))
	}
	digest := sha256.Sum256([]byte(kbSegs[0] + "." + kbSegs[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("KB-JWT signature does not verify under the holder key")
	}
}

func TestInjiBuildVPTokenEmpty(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := injiBuildVPToken("", key, "n", "a"); err == nil {
		t.Error("expected error on empty SD-JWT")
	}
}

// TestInjiHeldPresentable covers the presentable-credential lookup: an SD-JWT
// with a retained holder key is presentable (key non-nil); a W3C ldp_vc is
// presentable with NO key (unsigned ldp_vp, F23); an unknown id or an SD-JWT
// whose key wasn't retained are not.
func TestInjiHeldPresentable(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, _ := marshalECKeyPEM(key)
	sd := sampleSDJWT(t)
	sdID := vcID(sd)
	w3c := `{"type":["TestaW3C","VerifiableCredential"],"credentialSubject":{"id":"did:jwk:x"}}`
	sess := &Session{
		InjiClaimedVCs: []string{sd, w3c},
		InjiHolderKeys: map[string]string{sdID: pemStr},
	}
	if c, k, ok := injiHeldPresentable(sess, sdID); !ok || c != sd || k == nil {
		t.Fatalf("SD-JWT with key: ok=%v compactMatch=%v key=%v", ok, c == sd, k != nil)
	}
	if c, k, ok := injiHeldPresentable(sess, vcID(w3c)); !ok || c != w3c || k != nil {
		t.Errorf("W3C must be presentable with nil key: ok=%v match=%v keyNil=%v", ok, c == w3c, k == nil)
	}
	if _, _, ok := injiHeldPresentable(sess, "unknown"); ok {
		t.Error("unknown id must not be presentable")
	}
	noKey := &Session{InjiClaimedVCs: []string{sd}, InjiHolderKeys: map[string]string{}}
	if _, _, ok := injiHeldPresentable(noKey, sdID); ok {
		t.Error("SD-JWT without a retained key must not be presentable")
	}
}

// TestInjiW3CHelpers covers the F23 W3C ldp_vp helpers: format detection, title/
// field extraction, and the unsigned VerifiablePresentation wrapping.
func TestInjiW3CHelpers(t *testing.T) {
	vc := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["TestaW3C","VerifiableCredential"],"issuer":"did:web:x","credentialSubject":{"id":"did:jwk:zzz","last_name":"Ochieng","testa_id":"42"}}`
	sd := sampleSDJWT(t)

	if !injiIsW3C(vc) || !injiIsW3C("  {\"a\":1}") {
		t.Error("JSON objects (incl. leading space) should be W3C")
	}
	if injiIsW3C(sd) {
		t.Error("compact SD-JWT should not be W3C")
	}

	if got := injiW3CTitle(vc); got != "TestaW3C" {
		t.Errorf("title = %q", got)
	}
	if got := injiW3CTitle(`{"type":"VerifiableCredential"}`); got != "In-app Inji credential" {
		t.Errorf("string-type fallback = %q", got)
	}
	if got := injiW3CTitle("not json"); got != "In-app Inji credential" {
		t.Errorf("bad-json fallback = %q", got)
	}

	if f := injiW3CFields(vc); len(f) != 2 || f[0] != "last_name" || f[1] != "testa_id" {
		t.Errorf("fields = %v, want sorted [last_name testa_id]", f)
	}

	if got := injiPresentLabel(vc); got != "TestaW3C" {
		t.Errorf("W3C label = %q", got)
	}
	if got := injiPresentLabel(sd); got != injiSDJWTVct(sd) {
		t.Errorf("SD-JWT label = %q, want the vct", got)
	}

	tok, err := injiBuildW3CVPToken(vc)
	if err != nil {
		t.Fatal(err)
	}
	var vp map[string]any
	if err := json.Unmarshal([]byte(tok), &vp); err != nil {
		t.Fatal(err)
	}
	if ts, _ := vp["type"].([]any); len(ts) != 1 || ts[0] != "VerifiablePresentation" {
		t.Errorf("vp type = %v", vp["type"])
	}
	if vp["holder"] != "did:jwk:zzz" {
		t.Errorf("holder = %v", vp["holder"])
	}
	if ctx, _ := vp["@context"].([]any); len(ctx) < 1 || ctx[0] != "https://www.w3.org/ns/credentials/v2" {
		t.Errorf("vp @context = %v", vp["@context"])
	}
	creds, _ := vp["verifiableCredential"].([]any)
	if len(creds) != 1 {
		t.Fatalf("wrapped credential count = %d", len(creds))
	}
	if inner, _ := creds[0].(map[string]any); inner["issuer"] != "did:web:x" {
		t.Errorf("wrapped vc issuer = %v", creds[0])
	}
	if _, err := injiBuildW3CVPToken("not json"); err == nil {
		t.Error("expected error wrapping non-JSON")
	}
}
