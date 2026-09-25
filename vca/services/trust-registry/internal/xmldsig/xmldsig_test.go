// SPDX-License-Identifier: Apache-2.0

package xmldsig

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// now sits inside the validity of the fixture certificates (2026 to 2036).
var now = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func certificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(fixture(t, name))
	if block == nil {
		t.Fatalf("%s holds no PEM block", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestCanonicalMatchesLxml compares the exclusive canonical form with the
// output of lxml for the same documents.
func TestCanonicalMatchesLxml(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"prefixes": {
			`<a:root xmlns:a="urn:a" xmlns:b="urn:b" xmlns:unused="urn:u" z="1" b:y="2" a:x="3"><b:child xmlns:b="urn:b" b:k="v"/><a:e>t &amp; &lt; &gt; "q"</a:e></a:root>`,
			`<a:root xmlns:a="urn:a" xmlns:b="urn:b" z="1" a:x="3" b:y="2"><b:child b:k="v"></b:child><a:e>t &amp; &lt; &gt; "q"</a:e></a:root>`,
		},
		"default": {
			"<root xmlns=\"urn:d\" attr=\"a\tb\nc\"><inner xmlns=\"\"><deep xmlns=\"urn:d\"/></inner><x xml:lang=\"en\">text</x></root>",
			`<root xmlns="urn:d" attr="a b c"><inner xmlns=""><deep xmlns="urn:d"></deep></inner><x xml:lang="en">text</x></root>`,
		},
		"texts": {
			"<?xml version=\"1.0\"?>\n<!-- c --><r><![CDATA[a<b]]><!-- inner --><e a=\"&quot;&amp;&lt;&gt;\"/>\r\n</r>\n",
			"<r>a&lt;b<e a=\"&quot;&amp;&lt;>\"></e>\n</r>",
		},
		"references": {
			"<r a=\"1&#xD;&#10;2\">x&#13;y\r\nz</r>",
			"<r a=\"1&#xD;&#xA;2\">x&#xD;y\nz</r>",
		},
		"instruction": {
			`<r><?pi data?><e a="x&#9;y"/></r>`,
			"<r><?pi data?><e a=\"x&#x9;y\"></e></r>",
		},
	}
	for name, c := range cases {
		got, err := Canonical([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != c.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, c.want)
		}
	}
}

func TestCanonicalRefusesBadDocuments(t *testing.T) {
	for name, in := range map[string]string{
		"doctype":  `<!DOCTYPE r [<!ENTITY x "y">]><r/>`,
		"unbound":  `<p:r/>`,
		"unbound2": `<r p:a="1"/>`,
		"broken":   `<r>`,
		"empty":    ``,
		"two":      `<r/><s/>`,
		"stray":    `<r/>text`,
		"private":  "<r>\ue009</r>",
	} {
		if _, err := Canonical([]byte(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestVerifyRSAFixtureChainsToAnchor checks a list that a certificate
// issued by the anchor signed, with RSA-SHA256 over the whole document.
func TestVerifyRSAFixtureChainsToAnchor(t *testing.T) {
	signer, err := Verify(fixture(t, "tsl-rsa.xml"), []*x509.Certificate{certificate(t, "anchor.pem")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Subject.CommonName != "Trusted List Signer" {
		t.Fatalf("signer = %s", signer.Subject)
	}
}

// TestVerifyECDSAFixtureSignedByAnchor checks a list that the anchor
// itself signed, with ECDSA-SHA256 and a reference to the root Id.
func TestVerifyECDSAFixtureSignedByAnchor(t *testing.T) {
	anchor := certificate(t, "anchor.pem")
	signer, err := Verify(fixture(t, "tsl-ecdsa.xml"), []*x509.Certificate{certificate(t, "other.pem"), anchor}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Equal(anchor) {
		t.Fatalf("signer = %s", signer.Subject)
	}
}

// TestTamperedFixtureFails changes one service status, one signature
// byte, and one digest. Each copy fails.
func TestTamperedFixtureFails(t *testing.T) {
	anchors := []*x509.Certificate{certificate(t, "anchor.pem")}
	for _, name := range []string{"tsl-rsa.xml", "tsl-ecdsa.xml"} {
		doc := fixture(t, name)
		body := bytes.Replace(doc, []byte("Svcstatus/withdrawn"), []byte("Svcstatus/granted"), 1)
		if _, err := Verify(body, anchors, now); !errors.Is(err, ErrDigest) {
			t.Errorf("%s: a changed body = %v, want ErrDigest", name, err)
		}
		sig := tamperBetween(t, doc, "<ds:SignatureValue>", "</ds:SignatureValue>")
		if _, err := Verify(sig, anchors, now); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: a changed signature = %v, want ErrSignature", name, err)
		}
		digest := tamperBetween(t, doc, "<ds:DigestValue>", "</ds:DigestValue>")
		if _, err := Verify(digest, anchors, now); err == nil {
			t.Errorf("%s: a changed digest passed", name)
		}
	}
}

// tamperBetween flips one base64 character inside the first element.
func tamperBetween(t *testing.T, doc []byte, open, closing string) []byte {
	t.Helper()
	s := string(doc)
	i := strings.Index(s, open) + len(open) + 4
	if i < len(open)+4 || i >= strings.Index(s, closing) {
		t.Fatalf("no %s in the fixture", open)
	}
	c := byte('A')
	if s[i] == 'A' {
		c = 'B'
	}
	return []byte(s[:i] + string(c) + s[i+1:])
}

func TestAnotherAnchorFails(t *testing.T) {
	for _, name := range []string{"tsl-rsa.xml", "tsl-ecdsa.xml"} {
		if _, err := Verify(fixture(t, name), []*x509.Certificate{certificate(t, "other.pem")}, now); !errors.Is(err, ErrAnchor) {
			t.Errorf("%s: another anchor = %v, want ErrAnchor", name, err)
		}
	}
	if _, err := Verify(fixture(t, "tsl-rsa.xml"), nil, now); !errors.Is(err, ErrAnchor) {
		t.Errorf("no anchor = %v, want ErrAnchor", err)
	}
}

func TestExpiredCertificateFails(t *testing.T) {
	anchors := []*x509.Certificate{certificate(t, "anchor.pem")}
	later := time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{"tsl-rsa.xml", "tsl-ecdsa.xml"} {
		if _, err := Verify(fixture(t, name), anchors, later); !errors.Is(err, ErrAnchor) {
			t.Errorf("%s: after expiry = %v, want ErrAnchor", name, err)
		}
	}
}

func TestVerifyRefusesUnsupportedShapes(t *testing.T) {
	anchors := []*x509.Certificate{certificate(t, "anchor.pem")}
	doc := string(fixture(t, "tsl-rsa.xml"))
	cases := map[string]string{
		"no signature":   strings.Replace(doc, "ds:Signature ", "ds:Signed ", 1),
		"inclusive c14n": strings.Replace(doc, `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"`, `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"`, 1),
		"sha1 digest":    strings.Replace(doc, "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2000/09/xmldsig#sha1", 1),
		"rsa sha1":       strings.Replace(doc, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 1),
		"xpath":          strings.Replace(doc, "http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/1999/REC-xpath-19991116", 1),
		"other uri":      strings.Replace(doc, `URI=""`, `URI="#elsewhere"`, 1),
		"external uri":   strings.Replace(doc, `URI=""`, `URI="https://example.org/list.xml"`, 1),
		"no key":         cut(doc, "<ds:KeyInfo>", "</ds:KeyInfo>"),
		"bad key":        strings.Replace(doc, "<ds:X509Certificate>", "<ds:X509Certificate>AAAA", 1),
		"bad base64":     strings.Replace(doc, "<ds:SignatureValue>", "<ds:SignatureValue>***", 1),
		"no reference":   cut(doc, "<ds:Reference", "</ds:Reference>"),
		"no c14n last":   cut(doc, `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"`, "/>"),
		"prefix list":    strings.Replace(doc, `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`, `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="tsl"/></ds:Transform>`, 1),
		"not xml":        "not xml",
		"two signatures": strings.Replace(doc, "</tsl:TrustServiceStatusList>", doc[strings.Index(doc, "<ds:Signature"):strings.Index(doc, "</ds:Signature>")]+"</ds:Signature></tsl:TrustServiceStatusList>", 1),
	}
	for name, in := range cases {
		if in == doc {
			t.Fatalf("%s: the case changed nothing", name)
		}
		if _, err := Verify([]byte(in), anchors, now); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A duplicate Id makes the reference ambiguous.
	ecdsa := string(fixture(t, "tsl-ecdsa.xml"))
	dup := strings.Replace(ecdsa, "<tsl:SchemeInformation>", `<tsl:SchemeInformation Id="tsl">`, 1)
	if _, err := Verify([]byte(dup), anchors, now); err == nil {
		t.Error("a duplicate Id passed")
	}
	// A reference to an element that is not the document element leaves
	// the list unsigned, which is the shape of a wrapping attack.
	inner := strings.Replace(strings.Replace(ecdsa, `URI="#tsl"`, `URI="#scheme"`, 1), "<tsl:SchemeInformation>", `<tsl:SchemeInformation Id="scheme">`, 1)
	if _, err := Verify([]byte(inner), anchors, now); err == nil {
		t.Error("a reference to an inner element passed")
	}
}

// cut removes the text from the first open to the first closing after it.
func cut(doc, open, closing string) string {
	i := strings.Index(doc, open)
	j := strings.Index(doc[i:], closing)
	return doc[:i] + doc[i+j+len(closing):]
}
