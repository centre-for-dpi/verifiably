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
	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, carrier := range append([]ingest.Carrier{ingest.CarrierUnknown}, ingest.Carriers...) {
			_, _ = ingest.Decode(data, ingest.Options{Carrier: carrier, XML: ingest.XMLConfig{Path: "root.vc"}})
		}
	})
}

func FuzzDecodeText(f *testing.F) {
	f.Add(sdjwtToken)
	f.Add("{}")
	f.Add("~~~")
	f.Add("NCFOXN%TS3DH")
	f.Fuzz(func(_ *testing.T, text string) {
		_, _ = ingest.DecodeText(text)
		_, _ = ingest.DecodeVPToken(text)
	})
}

func FuzzDecodeClaim169(f *testing.F) {
	f.Add("NCFOXN%TS3DH")
	f.Add("HC1:NCFOXN%TS3DH")
	f.Add("")
	f.Fuzz(func(_ *testing.T, text string) {
		_, _, _ = ingest.DecodeClaim169(text)
	})
}

func FuzzDecodeXML(f *testing.F) {
	f.Add([]byte("<root><vc>a</vc></root>"), "root.vc")
	f.Add([]byte("<root a='1'/>"), "root.@a")
	f.Add([]byte("<"), "root")
	f.Fuzz(func(_ *testing.T, data []byte, path string) {
		_, _ = ingest.DecodeXML(data, ingest.XMLConfig{Path: path})
		_, _ = ingest.DecodeXML(data, ingest.XMLConfig{Path: path, Encoding: ingest.XMLBase64})
	})
}

func FuzzExtractPDFImages(f *testing.F) {
	f.Add([]byte("%PDF-1.7\n1 0 obj\n<< /Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 >>\nstream\nx\nendstream\nendobj\n"))
	f.Add([]byte("%PDF-"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ingest.ExtractPDFImages(data)
	})
}
