// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// mdocItem encodes one IssuerSignedItem as tag 24 over its CBOR bytes.
func mdocItem(t *testing.T, id uint, name string, value any) cbor.Tag {
	t.Helper()
	raw, err := cbor.Marshal(map[string]any{
		"digestID": id, "random": []byte{1, 2, 3}, "elementIdentifier": name, "elementValue": value,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cbor.Tag{Number: 24, Content: raw}
}

// sampleIssuerSigned builds an IssuerSigned structure of ISO/IEC
// 18013-5: two elements in one namespace, an MSO with the doctype, the
// validity and the device key, and a certificate in the x5chain header.
func sampleIssuerSigned(t *testing.T, withCert bool) map[string]any {
	t.Helper()
	return buildIssuerSigned(t, mdocOptions{cert: withCert, deviceKey: true})
}

// mdocOptions shape a sample mDoc.
type mdocOptions struct {
	cert, chain, deviceKey bool
}

func buildIssuerSigned(t *testing.T, o mdocOptions) map[string]any {
	t.Helper()
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo := map[string]any{"deviceKey": map[int]any{1: 2, -1: 1}}
	if o.deviceKey {
		keyInfo = map[string]any{"deviceKey": map[int]any{1: 2, -1: 1, -2: device.X.FillBytes(make([]byte, 32)), -3: device.Y.FillBytes(make([]byte, 32))}}
	}
	mso, err := cbor.Marshal(map[string]any{
		"version": "1.0", "digestAlgorithm": "SHA-256", "docType": "org.example.residence.1",
		"deviceKeyInfo": keyInfo,
		"validityInfo": map[string]any{
			"signed":     cbor.Tag{Number: 0, Content: "2026-01-01T00:00:00Z"},
			"validFrom":  cbor.Tag{Number: 0, Content: "2026-01-01T00:00:00Z"},
			"validUntil": cbor.Tag{Number: 0, Content: "2027-01-01T00:00:00Z"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cbor.Marshal(cbor.Tag{Number: 24, Content: mso})
	if err != nil {
		t.Fatal(err)
	}
	protected, err := cbor.Marshal(map[int]any{1: -7})
	if err != nil {
		t.Fatal(err)
	}
	unprotected := map[int]any{}
	switch {
	case o.chain:
		unprotected[33] = [][]byte{selfSigned(t)}
	case o.cert:
		unprotected[33] = selfSigned(t)
	}
	return map[string]any{
		"nameSpaces": map[string]any{"org.example.residence": []any{
			mdocItem(t, 0, "fullName", "Jordan Example"),
			mdocItem(t, 1, "resident_since", cbor.Tag{Number: 1004, Content: "2021-03-15"}),
			mdocItem(t, 2, "portrait", []byte{0xff, 0xd8}),
			mdocItem(t, 3, "age_over_18", true),
			mdocItem(t, 4, "address", map[string]any{"city": "Demo City"}),
			mdocItem(t, 5, "codes", []any{"A", 1}),
			mdocItem(t, 6, "score", math.NaN()),
		}},
		"issuerAuth": []any{protected, unprotected, payload, []byte{0}},
	}
}

// selfSigned returns the DER bytes of a certificate of the issuer.
func selfSigned(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Residence Office", Country: []string{"KE"}},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestParseReadsAnMdoc reads an mDoc in each wrapper a wallet meets:
// IssuerSigned, a Document, and a DeviceResponse, binary or base64url.
// The view names the doctype, the claims by element identifier, the
// namespaces for a claim path, the validity, the device key and the
// issuer of the certificate.
func TestParseReadsAnMdoc(t *testing.T) {
	signed := sampleIssuerSigned(t, true)
	document := map[string]any{"docType": "org.example.residence.1", "issuerSigned": signed}
	for name, raw := range map[string][]byte{
		"issuer signed":   mustCBOR(t, signed),
		"base64url":       []byte(base64.RawURLEncoding.EncodeToString(mustCBOR(t, signed))),
		"padded":          []byte(base64.URLEncoding.EncodeToString(mustCBOR(t, signed))),
		"document":        mustCBOR(t, document),
		"device response": mustCBOR(t, map[string]any{"version": "1.0", "documents": []any{document}, "status": 0}),
	} {
		c, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		if c.Format != string(FormatMdoc) || c.PrimaryType() != "org.example.residence.1" {
			t.Fatalf("%s: view = %+v", name, c)
		}
		if c.Claims["fullName"] != "Jordan Example" || c.Claims["resident_since"] != "2021-03-15" ||
			c.Claims["age_over_18"] != "true" || c.Claims["portrait"] != "_9g" ||
			c.Claims["address"] != `{"city":"Demo City"}` || c.Claims["codes"] != `["A",1]` || c.Claims["score"] != "NaN" {
			t.Fatalf("%s: claims = %v", name, c.Claims)
		}
		ns, ok := c.Raw["org.example.residence"].(map[string]any)
		if !ok || ns["fullName"] != "Jordan Example" {
			t.Fatalf("%s: raw = %v", name, c.Raw)
		}
		from, until := c.TemporalBounds()
		if from.Year() != 2026 || until.Year() != 2027 {
			t.Fatalf("%s: window = %v %v", name, from, until)
		}
		if cnf, ok := c.Raw["cnf"].(map[string]any); !ok || cnf["jwk"] == nil {
			t.Fatalf("%s: no device key: %v", name, c.Raw["cnf"])
		}
		if c.Issuer != "CN=Residence Office,C=KE" {
			t.Fatalf("%s: issuer = %q", name, c.Issuer)
		}
	}
	// An mDoc discloses each element alone, so no claim is fixed.
	if fixed, err := FixedClaims(mustCBOR(t, signed)); err != nil || len(fixed) != 0 {
		t.Fatalf("FixedClaims = %v, %v", fixed, err)
	}
	if _, err := FixedClaims([]byte{0xa1}); err == nil {
		t.Fatal("FixedClaims read a broken mDoc")
	}
}

// TestParseMdocFaults covers what an mDoc reader refuses or leaves out.
func TestParseMdocFaults(t *testing.T) {
	plain := sampleIssuerSigned(t, false)
	c, err := FromMdoc(mustCBOR(t, plain))
	if err != nil || c.Issuer != "" || len(c.Claims) != 7 {
		t.Fatalf("no certificate: %+v, %v", c, err)
	}
	chained, err := FromMdoc(mustCBOR(t, buildIssuerSigned(t, mdocOptions{chain: true})))
	if err != nil || chained.Issuer != "CN=Residence Office,C=KE" || chained.Raw["cnf"] != nil {
		t.Fatalf("a chain and no device key: %+v, %v", chained, err)
	}
	bare := map[string]any{"nameSpaces": plain["nameSpaces"]}
	if c, err := FromMdoc(mustCBOR(t, bare)); err != nil || c.PrimaryType() != "" || len(c.Claims) != 7 {
		t.Fatalf("no issuer signature: %+v, %v", c, err)
	}
	broken := sampleIssuerSigned(t, false)
	broken["issuerAuth"] = []any{[]byte{}, map[int]any{33: []byte{1, 2}}, []byte{0x01}, []byte{}}
	if c, err := FromMdoc(mustCBOR(t, broken)); err != nil || c.PrimaryType() != "" || c.Issuer != "" {
		t.Fatalf("a broken MSO and certificate: %+v, %v", c, err)
	}
	for name, raw := range map[string][]byte{
		"not cbor":         {0xa1},
		"not a map":        mustCBOR(t, []any{1}),
		"no documents":     mustCBOR(t, map[string]any{"documents": []any{}}),
		"bad document":     mustCBOR(t, map[string]any{"documents": []any{1}}),
		"no name spaces":   mustCBOR(t, map[string]any{"issuerAuth": []any{}}),
		"bad name spaces":  mustCBOR(t, map[string]any{"nameSpaces": 1}),
		"bad item":         mustCBOR(t, map[string]any{"nameSpaces": map[string]any{"ns": []any{cbor.Tag{Number: 24, Content: []byte{0xff}}}}}),
		"bad base64":       []byte("!!"),
		"bad issuerSigned": mustCBOR(t, map[string]any{"docType": "x", "issuerSigned": 1}),
	} {
		if _, err := FromMdoc(raw); err == nil {
			t.Errorf("%s: FromMdoc accepted it", name)
		}
	}
	// Names of the elements in document order.
	names := MdocElements(mustCBOR(t, plain))
	if !slices.Equal(names[:4], []string{"org.example.residence.fullName", "org.example.residence.resident_since",
		"org.example.residence.portrait", "org.example.residence.age_over_18"}) || len(names) != 7 {
		t.Fatalf("MdocElements = %v", names)
	}
	withBad := mustCBOR(t, map[string]any{"nameSpaces": map[string]any{"ns": []any{
		cbor.Tag{Number: 24, Content: []byte{0xff}}, mdocItem(t, 0, "a", "b")}}})
	if got := MdocElements(withBad); !slices.Equal(got, []string{"ns.a"}) {
		t.Fatalf("MdocElements skips a broken item, got %v", got)
	}
	if MdocElements([]byte("!!")) != nil || MdocElements([]byte(base64.RawURLEncoding.EncodeToString(mustCBOR(t, []any{1})))) != nil {
		t.Fatal("a broken mDoc names elements")
	}
}

// TestMdocDiscloseKeepsTheChosenElements drops every element the holder
// did not choose. The issuer signature stays valid, because the MSO
// signs a digest per element.
func TestMdocDiscloseKeepsTheChosenElements(t *testing.T) {
	signed := mustCBOR(t, sampleIssuerSigned(t, true))
	keep := func(name string) bool { return name == "org.example.residence.fullName" }
	for name, raw := range map[string][]byte{"binary": signed, "base64url": []byte(base64.RawURLEncoding.EncodeToString(signed))} {
		out, err := MdocDisclose(raw, keep)
		if err != nil {
			t.Fatalf("%s: MdocDisclose: %v", name, err)
		}
		if (name == "base64url") != (DetectFormat(out) == FormatMdoc && out[0] != 0xa2) {
			t.Fatalf("%s: the output changed its encoding", name)
		}
		c, err := Parse(out)
		if err != nil || len(c.Claims) != 1 || c.Claims["fullName"] != "Jordan Example" || c.Issuer == "" {
			t.Fatalf("%s: disclosed = %+v, %v", name, c, err)
		}
	}
	document := mustCBOR(t, map[string]any{"docType": "x", "issuerSigned": sampleIssuerSigned(t, false)})
	if _, err := MdocDisclose(document, keep); err == nil {
		t.Fatal("MdocDisclose took a Document, which the browser store never holds")
	}
	if _, err := MdocDisclose([]byte("!!"), keep); err == nil {
		t.Fatal("MdocDisclose took broken input")
	}
}
