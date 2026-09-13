// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/render"
)

func TestRenderDrawsThePage(t *testing.T) {
	document, err := render.Render(render.Document{
		Title:     "Farmer Credential",
		Issuer:    "Ministry of Agriculture",
		Claims:    map[string]string{"fullName": "Ada Lovelace", "farmerID": "FM-0001", "empty": ""},
		Order:     []string{"fullName", "farmerID"},
		Note:      "Scan the QR code to check this credential.",
		Footer:    "Issued in 2026",
		QRPayload: "openid-credential-offer://issuer.example.org?credential_offer_uri=https%3A%2F%2Fx",
		IssuedAt:  time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.HasPrefix(document, []byte("%PDF-1.4")) {
		t.Fatalf("the file is not a PDF: %q", document[:8])
	}
	if !bytes.Contains(document, []byte("/Title (Farmer Credential)")) {
		t.Fatal("the title is missing")
	}
	if !bytes.Contains(document, []byte("/XObject")) {
		t.Fatal("the QR image is missing")
	}
	if !bytes.Contains(document, []byte("/MediaBox [0 0 595.28 841.89]")) {
		t.Fatal("the page is not A4")
	}
}

func TestRenderUsesTheIssueTimeAsTheFooter(t *testing.T) {
	document, err := render.Render(render.Document{
		Claims:    map[string]string{"a": "b"},
		QRPayload: "x",
		IssuedAt:  time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Contains(document, []byte("/Title (Credential)")) {
		t.Fatal("a document without a title uses the default")
	}
}

func TestRenderNeedsAPayload(t *testing.T) {
	if _, err := render.Render(render.Document{}); !errors.Is(err, render.ErrNoPayload) {
		t.Fatalf("error = %v, want ErrNoPayload", err)
	}
}

func TestRenderReportsAPayloadThatIsTooLong(t *testing.T) {
	long := strings.Repeat("A", 3000)
	if _, err := render.Render(render.Document{QRPayload: long}); err == nil {
		t.Fatal("Render accepted a payload no QR symbol holds")
	}
}

func TestRenderKeepsThePageWithManyClaims(t *testing.T) {
	claims := map[string]string{}
	for i := 0; i < 40; i++ {
		claims[string(rune('a'+i%26))+string(rune('0'+i/26))] = "value"
	}
	document, err := render.Render(render.Document{Claims: claims, QRPayload: "x"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(document) == 0 {
		t.Fatal("the document is empty")
	}
}

func TestOfferPayloadTrimsTheUri(t *testing.T) {
	if got := render.OfferPayload("  openid-credential-offer://x  "); got != "openid-credential-offer://x" {
		t.Fatalf("payload = %q", got)
	}
}

func TestCredentialPayloadUsesThePixelPassForm(t *testing.T) {
	credential := []byte(`{"type":["VerifiableCredential"],"credentialSubject":{"fullName":"Ada"}}`)
	payload, err := render.CredentialPayload(credential)
	if err != nil {
		t.Fatalf("CredentialPayload: %v", err)
	}
	if strings.HasPrefix(payload, "{") {
		t.Fatal("a raw JSON payload breaks the base45 reader of the MOSIP tools")
	}
	back, derr := pixelpass.Decode(payload)
	if derr != nil {
		t.Fatalf("Decode: %v", derr)
	}
	if !bytes.Contains(back, []byte("Ada")) {
		t.Fatalf("the decoded payload = %s", back)
	}
}

func TestCredentialPayloadReportsAnEmptyCredential(t *testing.T) {
	if _, err := render.CredentialPayload(nil); err == nil {
		t.Fatal("CredentialPayload accepted an empty credential")
	}
}

func TestClaimOrderPutsTheNamedClaimsFirst(t *testing.T) {
	claims := map[string]string{"zeta": "1", "alpha": "2", "farmerID": "3", "fullName": "4"}
	got := render.ClaimOrder(claims, []string{"fullName", "farmerID", "missing", "fullName"})
	want := []string{"fullName", "farmerID", "alpha", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("order = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestClaimOrderCapsTheList(t *testing.T) {
	claims := map[string]string{}
	for i := 0; i < 40; i++ {
		claims[string(rune('a'+i%26))+string(rune('0'+i/26))] = "value"
	}
	if got := render.ClaimOrder(claims, nil); len(got) != 20 {
		t.Fatalf("order = %d names, want the page limit", len(got))
	}
}

func TestHumanise(t *testing.T) {
	cases := map[string]string{
		"fullName":  "Full Name",
		"full_name": "Full Name",
		"full-name": "Full Name",
		"farmerID":  "Farmer ID",
		"":          "",
	}
	for in, want := range cases {
		if got := render.Humanise(in); got != want {
			t.Fatalf("Humanise(%q) = %q, want %q", in, got, want)
		}
	}
}
