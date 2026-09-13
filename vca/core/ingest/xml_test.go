// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
)

const soap = `<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vc="urn:example:vc">
  <soap:Body>
    <vc:Credential format="jwt">eyJhbGciOiJFUzI1NiJ9.e30.c2ln</vc:Credential>
  </soap:Body>
</soap:Envelope>`

func TestDecodeXMLText(t *testing.T) {
	got, err := ingest.DecodeXML([]byte(soap), ingest.XMLConfig{Path: "Envelope.Body.Credential"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "eyJhbGciOiJFUzI1NiJ9.e30.c2ln" {
		t.Errorf("text = %q", got)
	}
}

func TestDecodeXMLNamespaces(t *testing.T) {
	cfg := ingest.XMLConfig{
		Path:       "s:Envelope.s:Body.v:Credential",
		Namespaces: map[string]string{"s": "http://schemas.xmlsoap.org/soap/envelope/", "v": "urn:example:vc"},
	}
	if _, err := ingest.DecodeXML([]byte(soap), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Namespaces["v"] = "urn:other"
	if _, err := ingest.DecodeXML([]byte(soap), cfg); !errors.Is(err, ingest.ErrXMLPathNotFound) {
		t.Errorf("a wrong namespace wants ErrXMLPathNotFound, got %v", err)
	}
}

func TestDecodeXMLWildcard(t *testing.T) {
	got, err := ingest.DecodeXML([]byte(soap), ingest.XMLConfig{Path: "*.*.Credential"})
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Error("a wildcard step must match any element name")
	}
}

func TestDecodeXMLAttribute(t *testing.T) {
	got, err := ingest.DecodeXML([]byte(soap), ingest.XMLConfig{Path: "Envelope.Body.Credential.@format"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "jwt" {
		t.Errorf("attribute = %q", got)
	}
	_, err = ingest.DecodeXML([]byte(soap), ingest.XMLConfig{Path: "Envelope.Body.Credential.@missing"})
	if !errors.Is(err, ingest.ErrXMLPathNotFound) {
		t.Errorf("a missing attribute wants ErrXMLPathNotFound, got %v", err)
	}
}

func TestDecodeXMLBase64(t *testing.T) {
	inner := "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
	doc := "<root><vc>" + base64.StdEncoding.EncodeToString([]byte(inner)) + "</vc></root>"
	got, err := ingest.DecodeXML([]byte(doc), ingest.XMLConfig{Path: "root.vc", Encoding: ingest.XMLBase64})
	if err != nil {
		t.Fatal(err)
	}
	if got != inner {
		t.Errorf("base64 text = %q", got)
	}
	raw := "<root><vc>" + base64.RawStdEncoding.EncodeToString([]byte(inner)) + "</vc></root>"
	if got, err = ingest.DecodeXML([]byte(raw), ingest.XMLConfig{Path: "root.vc", Encoding: ingest.XMLBase64}); err != nil || got != inner {
		t.Errorf("unpadded base64 = %q, %v", got, err)
	}
	bad := "<root><vc>not base64 !!</vc></root>"
	if _, err := ingest.DecodeXML([]byte(bad), ingest.XMLConfig{Path: "root.vc", Encoding: ingest.XMLBase64}); err == nil {
		t.Error("text that is not base64 wants an error")
	}
}

func TestDecodeXMLErrors(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		cfg  ingest.XMLConfig
	}{
		{"empty path", soap, ingest.XMLConfig{Path: "  "}},
		{"empty step", soap, ingest.XMLConfig{Path: "a..b"}},
		{"empty attribute", soap, ingest.XMLConfig{Path: "a.@"}},
		{"step after attribute", soap, ingest.XMLConfig{Path: "a.@b.c"}},
		{"attribute only", soap, ingest.XMLConfig{Path: "@b"}},
		{"deep path", soap, ingest.XMLConfig{Path: strings.Repeat("a.", ingest.MaxXMLDepth+1) + "b"}},
		{"unknown encoding", soap, ingest.XMLConfig{Path: "Envelope.Body.Credential", Encoding: "hex"}},
		{"missing path", soap, ingest.XMLConfig{Path: "Envelope.Header"}},
		{"broken document", "<root><a>", ingest.XMLConfig{Path: "root.a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ingest.DecodeXML([]byte(c.doc), c.cfg); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestDecodeXMLDeepDocument(t *testing.T) {
	doc := strings.Repeat("<a>", ingest.MaxXMLDepth+2) + "x" + strings.Repeat("</a>", ingest.MaxXMLDepth+2)
	if _, err := ingest.DecodeXML([]byte(doc), ingest.XMLConfig{Path: "a.b"}); err == nil {
		t.Error("a document deeper than the limit wants an error")
	}
}

func TestIsXML(t *testing.T) {
	if !ingest.IsXML([]byte("\ufeff  <root/>")) {
		t.Error("a byte order mark before the first tag is XML")
	}
	if ingest.IsXML([]byte("{}")) {
		t.Error("JSON is not XML")
	}
}
