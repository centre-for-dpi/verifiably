// SPDX-License-Identifier: Apache-2.0

package holderkey_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/holderkey"
)

// at is the clock of the tests.
var at = time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)

// browserKey is a P-256 key as the browser holds it, and its public JWK
// as the page sends it.
func browserKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(priv.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(raw)
}

// signES256 signs a signing input as WebCrypto does: the raw r and s of
// 32 bytes each, base64url encoded.
func signES256(t *testing.T, priv *ecdsa.PrivateKey, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// parts reads the header and the payload of a signing input.
func parts(t *testing.T, input string) (map[string]any, map[string]any) {
	t.Helper()
	segs := strings.Split(input, ".")
	if len(segs) != 2 {
		t.Fatalf("the signing input has %d parts, want 2", len(segs))
	}
	var hdr, payload map[string]any
	for i, out := range []*map[string]any{&hdr, &payload} {
		raw, err := base64.RawURLEncoding.DecodeString(segs[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	return hdr, payload
}

func TestParseKeyTakesAPublicP256KeyOnly(t *testing.T) {
	_, pub := browserKey(t)
	if _, err := holderkey.ParseKey(pub); err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := json.Marshal(jose.JWK{Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wide, err := json.Marshal(jose.JWK{Key: p384.Public()})
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := json.Marshal(jose.JWK{Key: edPub})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"private part": string(private), "P-384": string(wide), "Ed25519": string(ed), "not JSON": "{", "empty": "",
	} {
		if _, err := holderkey.ParseKey(raw); !errors.Is(err, holderkey.ErrKey) {
			t.Errorf("%s: err = %v, want ErrKey", name, err)
		}
	}
}

// TestProofSignedInTheBrowserPassesTheIssuerCheck: the portal builds the
// proof of OID4VCI 1.0 appendix F.1, the browser signs it, and the
// joined JWT verifies with the key in its own header.
func TestProofSignedInTheBrowserPassesTheIssuerCheck(t *testing.T) {
	priv, pub := browserKey(t)
	key, err := holderkey.ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	input, err := holderkey.ProofInput(key, "https://issuer.example.org", "c-nonce-1", at)
	if err != nil {
		t.Fatal(err)
	}
	hdr, payload := parts(t, input)
	if hdr["typ"] != holderkey.TypeProof || hdr["alg"] != "ES256" || hdr["jwk"] == nil {
		t.Fatalf("header = %v", hdr)
	}
	headerKey, ok := hdr["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("the proof header names no key: %v", hdr)
	}
	if _, private := headerKey["d"]; private {
		t.Fatal("the proof header carries a private part")
	}
	if payload["aud"] != "https://issuer.example.org" || payload["nonce"] != "c-nonce-1" || payload["iat"] != float64(at.Unix()) {
		t.Fatalf("payload = %v", payload)
	}
	jwt, err := holderkey.Join(input, signES256(t, priv, input), key)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	embedded, err := jose.JWKFromMap(headerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jose.Verify(jwt, embedded.Key, []jose.Algorithm{jose.ES256}); err != nil {
		t.Fatalf("the issuer check of the proof fails: %v", err)
	}
	other, _ := browserKey(t)
	if _, err := holderkey.Join(input, signES256(t, other, input), key); !errors.Is(err, holderkey.ErrSignature) {
		t.Fatalf("a signature of another key: err = %v", err)
	}
	if _, err := holderkey.Join(input, "not-a-signature", key); !errors.Is(err, holderkey.ErrSignature) {
		t.Fatalf("a broken signature: err = %v", err)
	}
}

// TestBindingSignedInTheBrowserPassesTheVerifierCheck: the key binding
// JWT of RFC 9901 covers the disclosed presentation with sd_hash, and
// core/sdjwt accepts it with the audience and the nonce of the request.
func TestBindingSignedInTheBrowserPassesTheVerifierCheck(t *testing.T) {
	priv, pub := browserKey(t)
	key, err := holderkey.ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	cnf, err := jose.JWKToMap(key)
	if err != nil {
		t.Fatal(err)
	}
	payload, discs, err := sdjwt.Conceal(map[string]any{"fullName": "Wanjiku Njeri", "farmerID": "FM-0042"}, []string{"fullName", "farmerID"})
	if err != nil {
		t.Fatal(err)
	}
	payload["iss"], payload["vct"], payload["cnf"] = "https://issuer.example.org", "FarmerRegistration", map[string]any{"jwk": cnf}
	jwt, err := jose.Sign(issuer, "issuer-key", "dc+sd-jwt", payload)
	if err != nil {
		t.Fatal(err)
	}
	presentation := sdjwt.Serialize(sdjwt.Presentation{IssuerJWT: jwt, Disclosures: discs[:1]})
	input, err := holderkey.BindingInput(presentation, "x509_san_dns:verifier.example.org", "n-0S6_WzA2Mj", at)
	if err != nil {
		t.Fatal(err)
	}
	hdr, claims := parts(t, input)
	if hdr["typ"] != sdjwt.TypeKB || hdr["alg"] != "ES256" {
		t.Fatalf("header = %v", hdr)
	}
	if claims["sd_hash"] != holderkey.SDHash(presentation) {
		t.Fatalf("sd_hash = %v", claims["sd_hash"])
	}
	kb, err := holderkey.Join(input, signES256(t, priv, input), key)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := issuer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the issuer key is a %T", issuer)
	}
	if _, err := sdjwt.Verify(presentation+kb, sdjwt.VerifyOptions{
		IssuerKey:         func(jose.Header, map[string]any) (crypto.PublicKey, error) { return signer.Public(), nil },
		RequireKeyBinding: true, Audience: "x509_san_dns:verifier.example.org", Nonce: "n-0S6_WzA2Mj", Now: at,
	}); err != nil {
		t.Fatalf("the verifier check of the key binding fails: %v", err)
	}
	if _, err := holderkey.BindingInput("no-tilde", "a", "n", at); err == nil {
		t.Fatal("a token with no trailing tilde gave a signing input")
	}
}

// TestHolderKeyOfACredential reads cnf.jwk of an SD-JWT, and nothing of a
// credential with no holder key.
func TestHolderKeyOfACredential(t *testing.T) {
	_, pub := browserKey(t)
	key, err := holderkey.ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cnf, err := jose.JWKToMap(key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := jose.Sign(issuer, "k", "dc+sd-jwt", map[string]any{"iss": "i", "cnf": map[string]any{"jwk": cnf}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := holderkey.Bound(bound + "~")
	if !ok {
		t.Fatal("a bound credential names no holder key")
	}
	if a, b := thumb(t, got), thumb(t, key); a != b {
		t.Fatalf("holder key %s, want %s", a, b)
	}
	free, err := jose.Sign(issuer, "k", "dc+sd-jwt", map[string]any{"iss": "i"})
	if err != nil {
		t.Fatal(err)
	}
	noJWK, err := jose.Sign(issuer, "k", "dc+sd-jwt", map[string]any{"iss": "i", "cnf": map[string]any{"kid": "k-1"}})
	if err != nil {
		t.Fatal(err)
	}
	badJWK, err := jose.Sign(issuer, "k", "dc+sd-jwt", map[string]any{"iss": "i", "cnf": map[string]any{"jwk": map[string]any{"kty": "EC"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{free + "~", noJWK + "~", badJWK + "~", "garbage", ""} {
		if _, ok := holderkey.Bound(token); ok {
			t.Errorf("%q names a holder key", token)
		}
	}
}

// thumb returns the thumbprint of a key.
func thumb(t *testing.T, k jose.JWK) string {
	t.Helper()
	out, err := jose.Thumbprint(k)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCheckBindingCoversTheAnswer: the portal accepts a key binding JWT
// of the browser only when the holder key signed it over this token,
// this audience and this nonce.
func TestCheckBindingCoversTheAnswer(t *testing.T) {
	priv, pub := browserKey(t)
	key, err := holderkey.ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	presented := "eyJhbGciOiJFUzI1NiJ9.e30.c2ln~WyJzYWx0IiwibmFtZSIsIkFkYSJd~"
	signed := func(presentation, aud, nonce string) string {
		input, berr := holderkey.BindingInput(presentation, aud, nonce, at)
		if berr != nil {
			t.Fatal(berr)
		}
		return input + "." + signES256(t, priv, input)
	}
	good := signed(presented, "verifier", "n-1")
	if err = holderkey.CheckBinding(good, presented, "verifier", "n-1", key); err != nil {
		t.Fatalf("CheckBinding: %v", err)
	}
	_, otherPub := browserKey(t)
	otherKey, err := holderkey.ParseKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		kb, token, aud, nonce string
		key                   jose.JWK
	}{
		"another token":    {good, presented + "WyJ4Il0~", "verifier", "n-1", key},
		"another audience": {good, presented, "someone", "n-1", key},
		"another nonce":    {good, presented, "verifier", "n-2", key},
		"another key":      {good, presented, "verifier", "n-1", otherKey},
		"not a JWT":        {"garbage", presented, "verifier", "n-1", key},
		"proof type":       {proofOf(t, priv, key), presented, "verifier", "n-1", key},
		"not JSON":         {notJSON(t, priv), presented, "verifier", "n-1", key},
	} {
		if err := holderkey.CheckBinding(c.kb, c.token, c.aud, c.nonce, c.key); err == nil {
			t.Errorf("%s: the portal accepted the key binding", name)
		}
	}
}

// proofOf returns a signed proof, which is no key binding JWT.
func proofOf(t *testing.T, priv *ecdsa.PrivateKey, key jose.JWK) string {
	t.Helper()
	input, err := holderkey.ProofInput(key, "verifier", "n-1", at)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + signES256(t, priv, input)
}

// notJSON returns a key binding JWT whose payload is no JSON object.
func notJSON(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(`{"alg":"ES256","typ":"kb+jwt"}`)) + "." + enc.EncodeToString([]byte("[1]"))
	return input + "." + signES256(t, priv, input)
}

// TestVPJWTOfAJwtCredential is ADR-083 decision 5: the holder key of a
// jwt_vc_json credential comes from cnf.jwk or from a did:jwk or did:key
// subject, the VP JWT names the holder, and CheckVP takes only the VP
// JWT of that key, audience, nonce and credential.
func TestVPJWTOfAJwtCredential(t *testing.T) {
	priv, raw := browserKey(t)
	key, err := holderkey.ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.JWKToMap(key)
	if err != nil {
		t.Fatal(err)
	}
	jwkDID, err := did.FromJWK(m)
	if err != nil {
		t.Fatal(err)
	}
	keyDID, err := did.FromPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	cred := func(claims map[string]any) string {
		signed, serr := jose.Sign(issuer, "k", "JWT", claims)
		if serr != nil {
			t.Fatal(serr)
		}
		return signed
	}
	for name, tc := range map[string]struct {
		claims map[string]any
		holder string
		kid    string
	}{
		"cnf":     {map[string]any{"sub": "urn:holder", "cnf": map[string]any{"jwk": m}}, "urn:holder", ""},
		"did:jwk": {map[string]any{"sub": jwkDID}, jwkDID, jwkDID + "#0"},
		"did:key": {map[string]any{"vc": map[string]any{"credentialSubject": map[string]any{"id": keyDID}}}, keyDID, keyDID + "#" + strings.TrimPrefix(keyDID, "did:key:")},
	} {
		token := cred(tc.claims)
		got, holder, ok := holderkey.BoundJWT(token)
		if !ok || holder != tc.holder || thumb(t, got) != thumb(t, key) || !holderkey.Binds(token) {
			t.Fatalf("%s: BoundJWT = %q, %v", name, holder, ok)
		}
		input, err := holderkey.VPInput(token, holder, got, "https://verifier.example", "n-1", time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		hdr, payload := parts(t, input)
		if hdr["kid"] != nil && hdr["kid"] != tc.kid || (tc.kid != "" && hdr["kid"] != tc.kid) || payload["iss"] != tc.holder {
			t.Fatalf("%s: header %v payload %v", name, hdr, payload)
		}
		vp := input + "." + signES256(t, priv, input)
		if err := holderkey.CheckVP(vp, token, "https://verifier.example", "n-1", key); err != nil {
			t.Fatalf("%s: CheckVP: %v", name, err)
		}
		other, _ := browserKey(t)
		for why, bad := range map[string]error{
			"another key":        holderkey.CheckVP(input+"."+signES256(t, other, input), token, "https://verifier.example", "n-1", key),
			"another audience":   holderkey.CheckVP(vp, token, "https://other.example", "n-1", key),
			"another credential": holderkey.CheckVP(vp, "other", "https://verifier.example", "n-1", key),
		} {
			if bad == nil {
				t.Errorf("%s: %s passed", name, why)
			}
		}
	}
	// No holder id leaves iss out of the VP JWT.
	if input, err := holderkey.VPInput("t", "", key, "a", "n", time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	} else if _, payload := parts(t, input); payload["iss"] != nil {
		t.Fatalf("payload %v", payload)
	}
	if _, err := holderkey.VPInput("t", "", jose.JWK{}, "a", "n", time.Unix(0, 0)); err == nil {
		t.Fatal("VPInput took an empty key")
	}
	for name, token := range map[string]string{
		"no key":    cred(map[string]any{"sub": "did:web:holder.example"}),
		"bad cnf":   cred(map[string]any{"cnf": map[string]any{"jwk": map[string]any{"kty": "nope"}}}),
		"not a jwt": "nope",
		"an sd-jwt": cred(map[string]any{"sub": jwkDID}) + "~",
	} {
		if _, _, ok := holderkey.BoundJWT(token); ok {
			t.Errorf("%s: BoundJWT found a key", name)
		}
	}
	if holderkey.Binds("nope") {
		t.Fatal("Binds took a broken credential")
	}
	// A payload that is no JSON object fails the check.
	broken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`[1]`))
	if err := holderkey.CheckVP(broken+"."+signES256(t, priv, broken), "t", "a", "n", key); !errors.Is(err, holderkey.ErrVP) {
		t.Fatalf("broken payload: %v", err)
	}
}
