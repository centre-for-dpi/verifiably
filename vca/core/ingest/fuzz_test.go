// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
)

// The decoders take bytes from the public. They must never panic
// (ADR-023 decision 2). Each fuzz target runs its seed corpus in an
// ordinary test run.

func FuzzDecode(f *testing.F) {
	f.Add([]byte(sdjwtToken))
	f.Add([]byte(`{"type":["VerifiablePresentation"],"verifiableCredential":["a"]}`))
	f.Add([]byte("openid4vp://authorize?nonce=1"))
	f.Add([]byte("%PDF-1.7\n1 0 obj\n<< /Subtype /Image /Filter /FlateDecode >>\nstream\nx\nendstream\nendobj\n"))
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Add([]byte("NCFOXN%TS3DH"))
	f.Add([]byte("<root><vc>a</vc></root>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, carrier := range append([]ingest.Carrier{ingest.CarrierUnknown}, ingest.Carriers...) {
			if _, err := ingest.Decode(data, ingest.Options{Carrier: carrier, XML: ingest.XMLConfig{Path: "root.vc"}}); err != nil && err.Error() == "" {
				t.Fatalf("ingest.Decode must describe the failure")
			}
		}
	})
}

func FuzzDecodeText(f *testing.F) {
	f.Add(sdjwtToken)
	f.Add("{}")
	f.Add("~~~")
	f.Add("NCFOXN%TS3DH")
	f.Fuzz(func(t *testing.T, text string) {
		if _, err := ingest.DecodeText(text); err != nil && err.Error() == "" {
			t.Fatalf("ingest.DecodeText must describe the failure")
		}
		if _, err := ingest.DecodeVPToken(text); err != nil && err.Error() == "" {
			t.Fatalf("ingest.DecodeVPToken must describe the failure")
		}
	})
}

func FuzzDecodeClaim169(f *testing.F) {
	f.Add("NCFOXN%TS3DH")
	f.Add("HC1:NCFOXN%TS3DH")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		if _, _, err := ingest.DecodeClaim169(text); err != nil && err.Error() == "" {
			t.Fatalf("ingest.DecodeClaim169 must describe the failure")
		}
	})
}

func FuzzDecodeXML(f *testing.F) {
	f.Add([]byte("<root><vc>a</vc></root>"), "root.vc")
	f.Add([]byte("<root a='1'/>"), "root.@a")
	f.Add([]byte("<"), "root")
	f.Fuzz(func(t *testing.T, data []byte, path string) {
		if _, err := ingest.DecodeXML(data, ingest.XMLConfig{Path: path}); err != nil && err.Error() == "" {
			t.Fatalf("ingest.DecodeXML must describe the failure")
		}
		if _, err := ingest.DecodeXML(data, ingest.XMLConfig{Path: path, Encoding: ingest.XMLBase64}); err != nil && err.Error() == "" {
			t.Fatalf("ingest.DecodeXML must describe the failure")
		}
	})
}

func FuzzExtractPDFImages(f *testing.F) {
	f.Add([]byte("%PDF-1.7\n1 0 obj\n<< /Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 >>\nstream\nx\nendstream\nendobj\n"))
	f.Add([]byte("%PDF-"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := ingest.ExtractPDFImages(data); err != nil && err.Error() == "" {
			t.Fatalf("ingest.ExtractPDFImages must describe the failure")
		}
	})
}
