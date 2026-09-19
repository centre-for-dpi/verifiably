// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
)

func b64(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sampleJWT() string {
	return b64(map[string]any{"alg": "ES256"}) + "." + b64(map[string]any{"iss": "did:web:issuer", "vc": map[string]any{"type": []any{"VerifiableCredential", "BirthCertificate"}}}) + ".sig"
}

func sampleSDJWT(t *testing.T) (string, []sdjwt.Disclosure) {
	t.Helper()
	payload := map[string]any{
		"iss": "did:web:issuer", "sub": "did:key:delegate", "vct": "PetAccessCredential",
		"onBehalfOf": "urn:pet:bosco", "allowedAction": "present", "iat": float64(1),
	}
	concealed, discs, err := sdjwt.Conceal(payload, []string{"allowedAction"})
	if err != nil {
		t.Fatal(err)
	}
	jwt := b64(map[string]any{"alg": "ES256"}) + "." + b64(concealed) + ".sig"
	return sdjwt.Serialize(sdjwt.Presentation{IssuerJWT: jwt, Disclosures: discs}), discs
}

func TestDetectFormat(t *testing.T) {
	sd, _ := sampleSDJWT(t)
	mdoc := []byte{0xa3, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e}
	cases := []struct {
		name string
		in   []byte
		want Format
	}{
		{"empty", []byte("  "), FormatUnknown},
		{"json-ld", []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`), FormatJSONLD},
		{"json", []byte(` {"vc":{}} `), FormatJSON},
		{"bad json", []byte(`{"vc":`), FormatUnknown},
		{"jwt", []byte(sampleJWT()), FormatJWT},
		{"sd-jwt", []byte(sd), FormatSDJWT},
		{"tilde but not jws", []byte("abc~"), FormatUnknown},
		{"mdoc cbor", mdoc, FormatMdoc},
		{"mdoc tag", []byte{0xd8, 0x18, 0x41, 0x00}, FormatMdoc},
		{"mdoc base64url", []byte(base64.RawURLEncoding.EncodeToString(mdoc)), FormatMdoc},
		{"mdoc base64url padded", []byte(base64.URLEncoding.EncodeToString(mdoc)), FormatMdoc},
		{"two segments", []byte("a.b"), FormatUnknown},
		{"empty segment", []byte(".b.c"), FormatUnknown},
		{"bad base64 segment", []byte("a!.b.c"), FormatUnknown},
		{"segments but not a header", []byte("YQ.YQ.YQ"), FormatUnknown},
		{"plain text", []byte("hello"), FormatUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectFormat(tc.in); got != tc.want {
				t.Fatalf("DetectFormat = %q, want %q", got, tc.want)
			}
		})
	}
}

// Regression: legacy TestFromVCObject_W3C.
func TestFromObjectW3C(t *testing.T) {
	obj := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential", "PetAccessCredential"},
		"issuer":   map[string]any{"id": "did:web:issuer", "name": "Registry"},
		"credentialSubject": map[string]any{
			"id": "did:key:delegate", "onBehalfOf": "urn:pet:bosco", "role": "Owner", "n": 2.0,
		},
	}
	got := FromObject(obj)
	if got.SubjectID != "did:key:delegate" || got.Issuer != "did:web:issuer" || got.Format != ModelVCDM2 {
		t.Fatalf("got %+v", got)
	}
	if got.Claims["onBehalfOf"] != "urn:pet:bosco" || got.Claims["role"] != "Owner" || got.Claims["n"] != "2" {
		t.Fatalf("Claims = %v", got.Claims)
	}
	if _, ok := got.Claims["id"]; ok {
		t.Fatal("credentialSubject.id must be the subject, not a claim")
	}
	if got.PrimaryType() != "PetAccessCredential" {
		t.Fatalf("PrimaryType = %q", got.PrimaryType())
	}
	v1 := FromObject(map[string]any{"@context": "https://www.w3.org/2018/credentials/v1"})
	if v1.Format != ModelVCDM1 {
		t.Fatalf("v1 format = %q", v1.Format)
	}
}

// Regression: legacy TestFromVCObject_JWTWrapper.
func TestFromObjectJWTWrapper(t *testing.T) {
	obj := map[string]any{
		"iss": "did:web:issuer", "sub": "did:key:fallback",
		"vc": map[string]any{
			"type":              []any{"VerifiableCredential", "BirthCertificate"},
			"credentialSubject": map[string]any{"subjectRef": "urn:person:child-1"},
		},
	}
	got := FromObject(obj)
	if got.Issuer != "did:web:issuer" || got.SubjectID != "did:key:fallback" || got.Format != string(FormatJWT) {
		t.Fatalf("got %+v", got)
	}
	if got.Claims["subjectRef"] != "urn:person:child-1" {
		t.Fatalf("Claims = %v", got.Claims)
	}
	c, err := FromJWT(" " + sampleJWT() + " ")
	if err != nil || c.Issuer != "did:web:issuer" || c.PrimaryType() != "BirthCertificate" {
		t.Fatalf("FromJWT = %+v, %v", c, err)
	}
	if _, err := FromJWT("nope"); err == nil {
		t.Fatal("bad jwt must fail")
	}
}

// Regression: legacy TestFromCompactSDJWT with digest matched disclosures.
func TestFromSDJWT(t *testing.T) {
	tok, discs := sampleSDJWT(t)
	got, err := FromSDJWT(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != string(FormatSDJWT) || got.SubjectID != "did:key:delegate" || got.Issuer != "did:web:issuer" {
		t.Fatalf("got %+v", got)
	}
	if got.Claims["onBehalfOf"] != "urn:pet:bosco" || got.Claims["allowedAction"] != "present" {
		t.Fatalf("Claims = %v", got.Claims)
	}
	if _, ok := got.Claims["iss"]; ok {
		t.Fatal("reserved claims must not be display claims")
	}
	if len(got.Types) != 1 || got.Types[0] != "PetAccessCredential" {
		t.Fatalf("Types = %v", got.Types)
	}
	// Regression: legacy TestFromCompactSDJWT_Garbage.
	if _, err := FromSDJWT("not-a-jwt"); err == nil {
		t.Fatal("garbage must fail")
	}
	if _, err := FromSDJWT("a.!!.c~"); err == nil {
		t.Fatal("bad payload must fail")
	}
	// A disclosure that matches no digest is rejected (legacy accepted it).
	stray, err := sdjwt.NewDisclosure("x", 1)
	if err != nil {
		t.Fatalf("sdjwt.NewDisclosure: %v", err)
	}
	if _, err := FromSDJWT(tok + stray.Encoded + "~"); err == nil {
		t.Fatal("unmatched disclosure must fail")
	}
	_ = discs
	noVct := FromResolvedSDJWT(map[string]any{"iss": "x"})
	if noVct.Types != nil {
		t.Fatalf("Types = %v", noVct.Types)
	}
}

func TestParse(t *testing.T) {
	sd, _ := sampleSDJWT(t)
	for _, in := range []string{sd, sampleJWT(), `{"@context":["https://www.w3.org/ns/credentials/v2"],"issuer":"did:web:a"}`, `{"issuer":"did:web:a"}`} {
		if c, err := Parse([]byte(in)); err != nil || c.Raw == nil {
			t.Fatalf("Parse(%q) = %+v, %v", in, c, err)
		}
	}
	if _, err := Parse([]byte{0xa1}); err == nil {
		t.Fatal("mdoc must report not decoded")
	}
	if _, err := Parse([]byte("hello")); err == nil {
		t.Fatal("unknown must fail")
	}
}

func TestPrimaryType(t *testing.T) {
	if (Credential{}).PrimaryType() != "" {
		t.Fatal("empty")
	}
	if (Credential{Types: []string{"VerifiableCredential"}}).PrimaryType() != "VerifiableCredential" {
		t.Fatal("fallback to first")
	}
}

// Regression: legacy backend TestTemporalBounds.
func TestTemporalBounds(t *testing.T) {
	nbf := float64(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	exp := float64(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	cases := []struct {
		name   string
		raw    map[string]any
		nb, na int // expected years, 0 for zero time
	}{
		{"vcdm2", map[string]any{"validFrom": "2020-01-01T00:00:00Z", "validUntil": "2030-01-01T00:00:00Z"}, 2020, 2030},
		{"vcdm1", map[string]any{"issuanceDate": "2019-06-01T00:00:00Z", "expirationDate": "2025-06-01T00:00:00Z"}, 2019, 2025},
		{"jwt", map[string]any{"nbf": nbf, "exp": exp}, 2021, 2029},
		{"absent", map[string]any{}, 0, 0},
		{"unparseable", map[string]any{"validUntil": "not-a-date", "exp": float64(0)}, 0, 0},
		{"flat", map[string]any{"valid_from": "2022-01-01T00:00:00Z", "valid_until": "2020-01-01T00:00:00Z"}, 2022, 2020},
		{"camel wins", map[string]any{"validUntil": "2030-01-01T00:00:00Z", "valid_until": "2020-01-01T00:00:00Z"}, 0, 2030},
		{"subject flat", map[string]any{"credentialSubject": map[string]any{"valid_from": "2021-01-01T00:00:00Z", "valid_until": "2020-06-01T00:00:00Z"}}, 2021, 2020},
		{"subject own dates ignored", map[string]any{"credentialSubject": map[string]any{"expirationDate": "2019-01-01T00:00:00Z", "validUntil": "2019-01-01T00:00:00Z"}}, 0, 0},
		{"top wins over subject", map[string]any{"validUntil": "2030-01-01T00:00:00Z", "credentialSubject": map[string]any{"valid_until": "2020-01-01T00:00:00Z"}}, 0, 2030},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nb, na := (Credential{Raw: tc.raw}).TemporalBounds()
			if year(nb) != tc.nb || year(na) != tc.na {
				t.Fatalf("bounds = %v %v", nb, na)
			}
		})
	}
}

func year(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	return t.Year()
}

func TestHelpers(t *testing.T) {
	if IssuerID(map[string]any{"id": "x"}) != "x" || IssuerID("y") != "y" || IssuerID(1) != "" {
		t.Fatal("IssuerID")
	}
	if got := AsStringSlice([]any{"a", 1, "b"}); len(got) != 2 {
		t.Fatalf("AsStringSlice = %v", got)
	}
	if got := AsStringSlice([]string{"a"}); len(got) != 1 {
		t.Fatalf("AsStringSlice = %v", got)
	}
	if AsStringSlice(1) != nil {
		t.Fatal("AsStringSlice(1)")
	}
	cases := []struct {
		in   any
		want string
	}{
		{"s", "s"}, {nil, ""}, {1.5, "1.5"}, {true, "true"},
		{map[string]any{"a": 1}, `{"a":1}`}, {make(chan int), "0x"},
	}
	for _, tc := range cases {
		got := Stringify(tc.in)
		if tc.want == "0x" {
			if len(got) < 3 || got[:2] != "0x" {
				t.Fatalf("Stringify(chan) = %q", got)
			}
			continue
		}
		if got != tc.want {
			t.Fatalf("Stringify(%v) = %q", tc.in, got)
		}
	}
}

func TestSchema(t *testing.T) {
	s := Schema{
		ID: "BankId_vc+sd-jwt", Name: "bank id card!", Variants: []SchemaVariant{
			{ID: "BankId_vc+sd-jwt", Std: "sd_jwt_vc", Vct: "https://i/BankId"},
			{ID: "BankId_jwt_vc_json", Std: ModelVCDM2},
		},
	}
	if !s.HasVariantID("BankId_vc+sd-jwt") || !s.HasVariantID("BankId_jwt_vc_json") || s.HasVariantID("x") {
		t.Fatal("HasVariantID")
	}
	if got := s.ApplyVariant("BankId_jwt_vc_json"); got.ID != "BankId_jwt_vc_json" || got.Std != ModelVCDM2 || got.Vct != "" {
		t.Fatalf("ApplyVariant = %+v", got)
	}
	if got := s.ApplyVariant("BankId_vc+sd-jwt"); got.Vct != "https://i/BankId" {
		t.Fatalf("ApplyVariant default = %+v", got)
	}
	if got := s.ApplyVariant("x"); got.ID != s.ID {
		t.Fatal("unknown variant must not change")
	}
	if s.BaseType() != "BankId" || (Schema{ID: "Plain"}).BaseType() != "Plain" {
		t.Fatal("BaseType")
	}
	if s.CustomTypeName() != "BankIdCard" {
		t.Fatalf("CustomTypeName = %q", s.CustomTypeName())
	}
	if (Schema{AdditionalTypes: []string{" Pinned "}}).CustomTypeName() != "Pinned" {
		t.Fatal("AdditionalTypes must win")
	}
	if (Schema{AdditionalTypes: []string{" "}, Name: "  "}).CustomTypeName() != "CustomCredential" {
		t.Fatal("empty name fallback")
	}
	if TypeName("9 lives A1") != "9LivesA1" {
		t.Fatalf("TypeName = %q", TypeName("9 lives A1"))
	}
	if (Schema{Expires: true}).ExpiresWithWindow() != true || (Schema{}).ExpiresWithWindow() {
		t.Fatal("ExpiresWithWindow")
	}
	if !(Schema{Fields: []FieldSpec{{Name: " Valid_Until "}}}).ExpiresWithWindow() {
		t.Fatal("legacy valid_until field must opt in")
	}
}

// Regression: legacy TestCredentialVct.
func TestCredentialVct(t *testing.T) {
	cases := []struct {
		name string
		s    Schema
		base string
		want string
	}{
		{"explicit Vct wins", Schema{ID: "custom-1", Vct: "https://issuer.example/vct/BankId"}, "https://verify.example.test", "https://issuer.example/vct/BankId"},
		{"host derived", Schema{ID: "custom-1"}, "https://verify.example.test", "https://verify.example.test/credentials/custom-1"},
		{"trailing slash trimmed", Schema{ID: "abc"}, "https://verify.example.test/", "https://verify.example.test/credentials/abc"},
		{"empty base falls back", Schema{ID: "abc"}, "", "http://localhost:8080/credentials/abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.s.CredentialVct(c.base); got != c.want {
				t.Errorf("CredentialVct(%q) = %q, want %q", c.base, got, c.want)
			}
		})
	}
}

func FuzzParseCredential(f *testing.F) {
	sd, _ := sampleSDJWTF(f)
	f.Add([]byte(sd))
	f.Add([]byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"credentialSubject":{"id":"x"}}`))
	f.Add([]byte{0xa1, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err != nil {
			return
		}
		_ = c.PrimaryType()
		_, _ = c.TemporalBounds()
	})
}

func sampleSDJWTF(f *testing.F) (string, []sdjwt.Disclosure) {
	concealed, discs, err := sdjwt.Conceal(map[string]any{"iss": "x", "a": 1}, []string{"a"})
	if err != nil {
		f.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		f.Fatalf("jose.GenerateKey: %v", err)
	}
	jwt, err := jose.Sign(key, "", "dc+sd-jwt", concealed)
	if err != nil {
		f.Fatalf("jose.Sign: %v", err)
	}
	return sdjwt.Serialize(sdjwt.Presentation{IssuerJWT: jwt, Disclosures: discs}), discs
}
