// SPDX-License-Identifier: Apache-2.0

package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type fixture struct {
	issuer  *ecdsa.PrivateKey
	holder  *ecdsa.PrivateKey
	payload map[string]any // concealed payload
	discs   []Disclosure
	tok     string // issuer JWT ~ disclosures ~
}

func b64json(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func newFixture(t *testing.T, extra map[string]any) fixture {
	t.Helper()
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	holder, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	holderJWK, err := jose.PublicJWK(holder, "")
	if err != nil {
		t.Fatalf("jose.PublicJWK: %v", err)
	}
	cnf, err := jose.JWKToMap(holderJWK)
	if err != nil {
		t.Fatalf("jose.JWKToMap: %v", err)
	}
	claims := map[string]any{
		"iss": "did:web:issuer", "sub": "did:key:delegate", "vct": "PetAccessCredential",
		"onBehalfOf": "urn:pet:bosco", "allowedAction": "present", "role": "Owner",
		"cnf": map[string]any{"jwk": cnf},
	}
	for k, v := range extra {
		claims[k] = v
	}
	payload, discs, err := Conceal(claims, []string{"allowedAction", "role"})
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := jose.Sign(issuer, "issuer-key", "dc+sd-jwt", payload)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{issuer: anyval.As[*ecdsa.PrivateKey](issuer), holder: anyval.As[*ecdsa.PrivateKey](holder), payload: payload, discs: discs}
	f.tok = Serialize(Presentation{IssuerJWT: jwt, Disclosures: discs})
	return f
}

func (f fixture) opts() VerifyOptions {
	return VerifyOptions{
		IssuerKey: func(hdr jose.Header, payload map[string]any) (crypto.PublicKey, error) {
			if hdr.Kid != "issuer-key" || payload["iss"] != "did:web:issuer" {
				return nil, errors.New("unknown issuer")
			}
			return &f.issuer.PublicKey, nil
		},
		Now: now, Audience: "https://verifier.example", Nonce: "n-1",
	}
}

func (f fixture) withKB(t *testing.T, aud, nonce string, iat time.Time) string {
	t.Helper()
	p, err := Parse(f.tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	kb, err := KeyBinding(p, f.holder, DefaultAlg, aud, nonce, iat)
	if err != nil {
		t.Fatal(err)
	}
	return f.tok + kb
}

// Regression: legacy TestFromCompactSDJWT, now with digest matched disclosures.
func TestParseAndResolve(t *testing.T) {
	f := newFixture(t, nil)
	p, err := Parse(f.tok)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Disclosures) != 2 || p.KeyBindingJWT != "" {
		t.Fatalf("presentation = %+v", p)
	}
	payload, err := jose.PeekPayload(p.IssuerJWT)
	if err != nil {
		t.Fatalf("jose.PeekPayload: %v", err)
	}
	claims, err := Resolve(payload, p.Disclosures)
	if err != nil {
		t.Fatal(err)
	}
	if claims["allowedAction"] != "present" || claims["role"] != "Owner" || claims["onBehalfOf"] != "urn:pet:bosco" {
		t.Fatalf("claims = %v", claims)
	}
	if _, ok := claims["_sd"]; ok {
		t.Fatal("_sd must be removed")
	}
	if _, ok := claims["_sd_alg"]; ok {
		t.Fatal("_sd_alg must be removed")
	}
	if _, ok := payload["_sd"]; !ok {
		t.Fatal("Resolve must not mutate its input")
	}
	// Holder withholds a disclosure: the claim is absent, no error.
	partial, err := Resolve(payload, p.Disclosures[:1])
	if err != nil || len(partial) != len(claims)-1 {
		t.Fatalf("partial = %v, %v", partial, err)
	}
	if Serialize(p) != f.tok {
		t.Fatal("Serialize must round trip")
	}
	withKB := f.withKB(t, "a", "n", now)
	p2, err := Parse(withKB)
	if err != nil || p2.KeyBindingJWT == "" {
		t.Fatalf("kb parse: %+v %v", p2, err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ name, tok string }{
		{"no tilde", "a.b.c"},
		{"issuer not jws", "abc~"},
		{"bad trailing", "a.b.c~x"},
		{"bad disclosure", "a.b.c~!!!~"},
		{"garbage", "not-a-jwt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.tok); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseDisclosure(t *testing.T) {
	enc := func(v any) string { return b64json(t, v) }
	bad := []struct{ name, seg string }{
		{"empty", ""},
		{"base64", "!!!"},
		{"json", base64.RawURLEncoding.EncodeToString([]byte("{"))},
		{"one element", enc([]any{"s"})},
		{"four elements", enc([]any{"s", "n", 1, 2})},
		{"empty salt", enc([]any{"", "n", 1})},
		{"salt not string", enc([]any{1, "n", 1})},
		{"empty name", enc([]any{"s", "", 1})},
		{"reserved _sd", enc([]any{"s", "_sd", 1})},
		{"reserved ...", enc([]any{"s", "...", 1})},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDisclosure(tc.seg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	d, err := ParseDisclosure(enc([]any{"salt", "US"}))
	if err != nil || d.Name != "" || d.Value != "US" || d.Salt != "salt" {
		t.Fatalf("array disclosure = %+v, %v", d, err)
	}
	d, err = ParseDisclosure(enc([]any{"salt", "given_name", "Ana"}))
	if err != nil || d.Name != "given_name" || d.Value != "Ana" {
		t.Fatalf("object disclosure = %+v, %v", d, err)
	}
	if _, chanErr := NewDisclosure("x", make(chan int)); chanErr == nil {
		t.Fatal("unmarshalable value must fail")
	}
	nd, err := NewDisclosure("", 5)
	if err != nil {
		t.Fatalf("NewDisclosure: %v", err)
	}
	back, err := ParseDisclosure(nd.Encoded)
	if err != nil || back.Name != "" || back.Value != float64(5) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
}

// Digest test vector from RFC 9901 section 4.2.3 (sha-256 of the example disclosure).
func TestDigest(t *testing.T) {
	const disc = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
	got, err := Digest(DefaultAlg, disc)
	if err != nil || got != "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0" {
		t.Fatalf("Digest = %q, %v", got, err)
	}
	for _, alg := range []string{"sha-384", "sha-512"} {
		if _, err := Digest(alg, disc); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Digest("md5", disc); err == nil {
		t.Fatal("md5 must fail")
	}
}

func TestConcealErrors(t *testing.T) {
	if _, _, err := Conceal(map[string]any{}, []string{"missing"}); err == nil {
		t.Fatal("missing claim must fail")
	}
	if _, _, err := Conceal(map[string]any{"c": make(chan int)}, []string{"c"}); err == nil {
		t.Fatal("unmarshalable claim must fail")
	}
}

func TestResolveNestedAndArrays(t *testing.T) {
	inner, err := NewDisclosure("street", "Main 1")
	if err != nil {
		t.Fatalf("NewDisclosure: %v", err)
	}
	innerDg, err := Digest("sha-384", inner.Encoded)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	addr, err := NewDisclosure("address", map[string]any{"_sd": []any{innerDg}, "city": "Lima"})
	if err != nil {
		t.Fatalf("NewDisclosure: %v", err)
	}
	addrDg, err := Digest("sha-384", addr.Encoded)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	us, err := NewDisclosure("", "US")
	if err != nil {
		t.Fatalf("NewDisclosure: %v", err)
	}
	usDg, err := Digest("sha-384", us.Encoded)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	de, err := NewDisclosure("", "DE")
	if err != nil {
		t.Fatalf("NewDisclosure: %v", err)
	}
	deDg, err := Digest("sha-384", de.Encoded)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	payload := map[string]any{
		"_sd_alg":       "sha-384",
		"_sd":           []any{addrDg, "unknown-digest"},
		"nationalities": []any{map[string]any{"...": usDg}, map[string]any{"...": deDg}, "FR", map[string]any{"k": "v"}},
		"nested":        map[string]any{"list": []any{1.0}},
	}
	// Disclose address, street and US. DE stays hidden.
	claims, err := Resolve(payload, []Disclosure{addr, inner, us})
	if err != nil {
		t.Fatal(err)
	}
	a := anyval.As[map[string]any](claims["address"])
	if a["street"] != "Main 1" || a["city"] != "Lima" {
		t.Fatalf("address = %v", a)
	}
	nats := anyval.As[[]any](claims["nationalities"])
	if len(nats) != 3 || nats[0] != "US" || nats[1] != "FR" {
		t.Fatalf("nationalities = %v", nats)
	}

	objInArray := map[string]any{"_sd_alg": "sha-384", "list": []any{map[string]any{"...": addrDg}}}
	if _, err := Resolve(objInArray, []Disclosure{addr}); err == nil {
		t.Fatal("object disclosure in array must fail")
	}
	arrayInObject := map[string]any{"_sd": []any{usDg256(t, us)}}
	if _, err := Resolve(arrayInObject, []Disclosure{us}); err == nil {
		t.Fatal("array disclosure as object claim must fail")
	}
	bad := []struct {
		name    string
		payload map[string]any
		discs   []Disclosure
	}{
		{"unsupported alg", map[string]any{"_sd_alg": "md5"}, nil},
		{"duplicate disclosure", map[string]any{"_sd_alg": "sha-384"}, []Disclosure{us, us}},
		{"unmatched disclosure", map[string]any{"_sd_alg": "sha-384"}, []Disclosure{us}},
		{"_sd not array", map[string]any{"_sd": "x"}, nil},
		{"digest not string", map[string]any{"_sd": []any{1.0}}, nil},
		{"claim already present", map[string]any{"_sd_alg": "sha-384", "_sd": []any{addrDg}, "address": "x"}, []Disclosure{addr}},
		{"digest twice in object", map[string]any{"_sd_alg": "sha-384", "_sd": []any{addrDg}, "b": map[string]any{"_sd": []any{addrDg}}}, []Disclosure{addr}},
		{"digest twice in array", map[string]any{"_sd_alg": "sha-384", "l": []any{map[string]any{"...": usDg}, map[string]any{"...": usDg}}}, []Disclosure{us}},
		{"error inside disclosed value", map[string]any{"_sd_alg": "sha-384", "_sd": []any{brokenDg(t)}}, []Disclosure{brokenObj(t)}},
		{"error inside array element", map[string]any{"l": []any{map[string]any{"_sd": "x"}}}, nil},
		{"error inside array disclosure", map[string]any{"_sd_alg": "sha-384", "l": []any{map[string]any{"...": badArrDg(t)}}}, []Disclosure{badArr(t)}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Resolve(tc.payload, tc.discs); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func usDg256(t *testing.T, d Disclosure) string {
	t.Helper()
	dg, err := Digest(DefaultAlg, d.Encoded)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return dg
}

// brokenObj is an object disclosure whose value carries an invalid _sd.
func brokenObj(t *testing.T) Disclosure {
	t.Helper()
	raw, err := json.Marshal([]any{"fixed-salt", "broken", map[string]any{"_sd": "x"}})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	d, err := ParseDisclosure(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	return d
}

func brokenDg(t *testing.T) string {
	t.Helper()
	dg, err := Digest("sha-384", brokenObj(t).Encoded)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return dg
}

func badArr(t *testing.T) Disclosure {
	t.Helper()
	// Deterministic salt so badArrDg matches.
	raw, err := json.Marshal([]any{"fixed-salt", map[string]any{"_sd": "x"}})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	d, err := ParseDisclosure(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	return d
}

func badArrDg(t *testing.T) string {
	t.Helper()
	dg, err := Digest("sha-384", badArr(t).Encoded)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return dg
}

func TestVerifyWithoutKeyBinding(t *testing.T) {
	f := newFixture(t, nil)
	res, resErr := Verify(f.tok, f.opts())
	if resErr != nil {
		t.Fatal(resErr)
	}
	if res.KeyBound || res.HolderKey == nil || res.Claims["role"] != "Owner" || res.Header.Kid != "issuer-key" {
		t.Fatalf("result = %+v", res)
	}
	o := f.opts()
	o.RequireKeyBinding = true
	if _, err := Verify(f.tok, o); !errors.Is(err, ErrNoKeyBinding) {
		t.Fatalf("want ErrNoKeyBinding, got %v", err)
	}
	// No cnf at all is fine without key binding.
	issuer, err := jose.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	jwt, err := jose.Sign(issuer, "", "dc+sd-jwt", map[string]any{"iss": "x"})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	pub, err := jose.PublicJWK(issuer, "")
	if err != nil {
		t.Fatalf("jose.PublicJWK: %v", err)
	}
	res, err = Verify(jwt+"~", VerifyOptions{IssuerKey: func(jose.Header, map[string]any) (crypto.PublicKey, error) { return pub.Key, nil }})
	if err != nil || res.HolderKey != nil {
		t.Fatalf("no cnf: %+v %v", res, err)
	}
}

func TestVerifyIssuerErrors(t *testing.T) {
	f := newFixture(t, nil)
	other, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	badKey := f.opts()
	badKey.IssuerKey = func(jose.Header, map[string]any) (crypto.PublicKey, error) {
		return &anyval.As[*ecdsa.PrivateKey](other).PublicKey, nil
	}
	resolverErr := f.opts()
	resolverErr.IssuerKey = func(jose.Header, map[string]any) (crypto.PublicKey, error) { return nil, errors.New("no key") }
	arrayPayload, err := jose.Sign(f.issuer, "issuer-key", "x", []int{1})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	expired := newFixture(t, map[string]any{"exp": float64(now.Add(-2 * time.Minute).Unix())})
	future := newFixture(t, map[string]any{"nbf": float64(now.Add(2 * time.Minute).Unix())})
	badCnf := newFixture(t, map[string]any{"cnf": map[string]any{"jwk": map[string]any{"kty": "EC"}}})
	unmatched := f.tok + f.discs[0].Encoded + "~"

	cases := []struct {
		name string
		tok  string
		opts VerifyOptions
		want error
	}{
		{"nil resolver", f.tok, VerifyOptions{}, nil},
		{"parse", "x", f.opts(), nil},
		{"bad header", "!!.b.c~", f.opts(), nil},
		{"bad payload", strings.SplitN(f.tok, ".", 2)[0] + ".!!.c~", f.opts(), nil},
		{"resolver error", f.tok, resolverErr, nil},
		{"wrong key", f.tok, badKey, jose.ErrSignatureInvalid},
		{"array payload", arrayPayload + "~", f.opts(), nil},
		{"expired", expired.tok, expired.opts(), ErrExpired},
		{"not yet valid", future.tok, future.opts(), ErrNotYetValid},
		{"bad cnf", badCnf.tok, badCnf.opts(), nil},
		{"unmatched disclosure", unmatched, f.opts(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.tok, tc.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// Within leeway the token is still accepted.
	fresh := newFixture(t, map[string]any{"exp": float64(now.Add(-30 * time.Second).Unix())})
	if _, err := Verify(fresh.tok, fresh.opts()); err != nil {
		t.Fatalf("leeway: %v", err)
	}
	strict := fresh.opts()
	strict.Leeway = time.Second
	strict.Algs = []jose.Algorithm{jose.ES256}
	if _, err := Verify(fresh.tok, strict); !errors.Is(err, ErrExpired) {
		t.Fatalf("strict leeway: %v", err)
	}
}

func TestVerifyKeyBinding(t *testing.T) {
	f := newFixture(t, nil)
	good := f.withKB(t, "https://verifier.example", "n-1", now.Add(-time.Minute))
	o := f.opts()
	o.RequireKeyBinding = true
	o.MaxKeyBindingAge = 5 * time.Minute
	res, err := Verify(good, o)
	if err != nil {
		t.Fatal(err)
	}
	if !res.KeyBound || res.KBClaims["nonce"] != "n-1" {
		t.Fatalf("result = %+v", res)
	}

	p, err := Parse(f.tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	otherHolder, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	wrongKey, err := KeyBinding(p, otherHolder, DefaultAlg, "https://verifier.example", "n-1", now)
	if err != nil {
		t.Fatalf("KeyBinding: %v", err)
	}
	wrongTyp, err := jose.Sign(f.holder, "", "JWT", map[string]any{"aud": "https://verifier.example", "nonce": "n-1", "iat": now.Unix()})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	arrayKB, err := jose.Sign(f.holder, "", TypeKB, []int{1})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	noIat, err := jose.Sign(f.holder, "", TypeKB, map[string]any{"aud": "https://verifier.example", "nonce": "n-1"})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	sdHash, err := Digest(DefaultAlg, f.tok)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	badHash, err := jose.Sign(f.holder, "", TypeKB, map[string]any{"aud": "https://verifier.example", "nonce": "n-1", "iat": now.Unix(), "sd_hash": "nope"})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	// A KB-JWT over a different disclosure set.
	reduced, err := KeyBinding(Presentation{IssuerJWT: p.IssuerJWT, Disclosures: p.Disclosures[:1]}, f.holder, DefaultAlg, "https://verifier.example", "n-1", now)
	if err != nil {
		t.Fatalf("KeyBinding: %v", err)
	}
	noCnf := newFixture(t, map[string]any{"cnf": "none"})
	noCnfKB, err := jose.Sign(f.holder, "", TypeKB, map[string]any{"aud": "https://verifier.example", "nonce": "n-1", "iat": now.Unix(), "sd_hash": sdHash})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}

	cases := []struct {
		name string
		tok  string
		opts VerifyOptions
	}{
		{"no cnf", noCnf.tok + noCnfKB, noCnf.opts()},
		{"wrong holder key", f.tok + wrongKey, o},
		{"wrong typ", f.tok + wrongTyp, o},
		{"array payload", f.tok + arrayKB, o},
		{"wrong aud", f.withKB(t, "https://other.example", "n-1", now), o},
		{"wrong nonce", f.withKB(t, "https://verifier.example", "n-2", now), o},
		{"no iat", f.tok + noIat, o},
		{"iat future", f.withKB(t, "https://verifier.example", "n-1", now.Add(10*time.Minute)), o},
		{"iat too old", f.withKB(t, "https://verifier.example", "n-1", now.Add(-time.Hour)), o},
		{"sd_hash mismatch", f.tok + badHash, o},
		{"sd_hash over other disclosures", f.tok + reduced, o},
		{"kb hash and payload ok but no verifier bad hash", f.tok + badHash, o},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(tc.tok, tc.opts); !errors.Is(err, ErrKeyBindingInvalid) {
				t.Fatalf("want ErrKeyBindingInvalid, got %v", err)
			}
		})
	}
	// Unbounded age accepts an old KB-JWT.
	unbounded := f.opts()
	if _, err := Verify(f.withKB(t, "https://verifier.example", "n-1", now.Add(-time.Hour)), unbounded); err != nil {
		t.Fatalf("unbounded age: %v", err)
	}
	// sd_hash follows _sd_alg of the issuer payload.
	if _, err := KeyBinding(p, f.holder, "md5", "a", "n", now); err == nil {
		t.Fatal("bad alg must fail")
	}
}

func FuzzParsePresentation(f *testing.F) {
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		f.Fatalf("jose.GenerateKey: %v", err)
	}
	claims := map[string]any{"iss": "x", "a": 1, "b": []any{"x"}}
	payload, discs, err := Conceal(claims, []string{"a"})
	if err != nil {
		f.Fatalf("Conceal: %v", err)
	}
	jwt, err := jose.Sign(issuer, "", "dc+sd-jwt", payload)
	if err != nil {
		f.Fatalf("jose.Sign: %v", err)
	}
	f.Add(Serialize(Presentation{IssuerJWT: jwt, Disclosures: discs}))
	f.Add("a.b.c~WyJzIiwibiIsMV0~")
	pub, err := jose.PublicJWK(issuer, "")
	if err != nil {
		f.Fatalf("jose.PublicJWK: %v", err)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		p, err := Parse(tok)
		if err != nil {
			return
		}
		if payload, err := jose.PeekPayload(p.IssuerJWT); err == nil {
			if _, err := Resolve(payload, p.Disclosures); err != nil && err.Error() == "" {
				t.Fatalf("Resolve must describe the failure")
			}
		}
		if _, err := Verify(tok, VerifyOptions{IssuerKey: func(jose.Header, map[string]any) (crypto.PublicKey, error) { return pub.Key, nil }}); err != nil && err.Error() == "" {
			t.Fatalf("Verify must describe the failure")
		}
	})
}
