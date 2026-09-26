// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"bytes"
	"compress/zlib"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// identityText builds a Claim 169 QR text: a COSE_Sign1 CWT, then zlib,
// then base45, per the MOSIP QR code specification 1.1.0.
func identityText(t *testing.T) string {
	t.Helper()
	protected, err := cbor.Marshal(map[int]any{1: -8})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := cbor.Marshal(map[int]any{1: "did:web:certify.inji.example",
		169: map[int]any{4: "Wanjiku Njeri", 8: "1984-03-12", 9: 2}})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[int]any{}, claims, []byte("signature")}})
	if err != nil {
		t.Fatal(err)
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return pixelpass.EncodeBase45(z.Bytes())
}

// TestIdentityQrCardOnlyWithChannel offers the identity QR card on a
// stack whose adapter lists the channel, and nowhere else.
func TestIdentityQrCardOnlyWithChannel(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	doc := body(t, h.post(t, "/issue/delivery", goodClaims()))
	if strings.Contains(doc, "CHANNEL_CLAIM169_QR") || strings.Contains(doc, "Identity QR (Claim 169)") {
		t.Fatal("the card shows on a stack that signs no identity QR")
	}
	if rec := h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_CLAIM169_QR")); len(h.issuance.requests) != 0 {
		t.Fatalf("the page issued over a channel the stack lacks: %d", rec.Code)
	}
	h.caps.caps.Channels = append(h.caps.caps.Channels, backendv1.Channel_CHANNEL_CLAIM169_QR)
	doc = body(t, h.post(t, "/issue/delivery", goodClaims()))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{`value="CHANNEL_CLAIM169_QR"`, "Identity QR (Claim 169)",
		"A printable document with the identity QR code the stack signs."} {
		if !strings.Contains(doc, want) {
			t.Errorf("delivery lacks %q", want)
		}
	}
	h.issuance.next = &issuancev1.Offer{Id: "offer-169", Channel: backendv1.Channel_CHANNEL_CLAIM169_QR}
	if rec := h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_CLAIM169_QR")); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if got := h.issuance.requests[0].GetDelivery().GetChannel(); got != backendv1.Channel_CHANNEL_CLAIM169_QR {
		t.Fatalf("channel %v", got)
	}
}

// TestIdentityQrResult shows the signed code, what it carries, and the
// document, and no offer link.
func TestIdentityQrResult(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	h.caps.caps.Channels = append(h.caps.caps.Channels, backendv1.Channel_CHANNEL_CLAIM169_QR)
	h.issuance.next = &issuancev1.Offer{Id: "offer-169", Channel: backendv1.Channel_CHANNEL_CLAIM169_QR,
		State: issuancev1.Offer_STATE_DELIVERED, IdentityQr: identityText(t), PdfRef: "ref-169"}
	h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_CLAIM169_QR"))
	doc := body(t, h.get(t, "/issue/offers/offer-169"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"Identity QR code ready", `<img class="qr" src="data:image/svg&#43;xml;base64,`,
		`alt="Identity QR code (Claim 169) of the Farmer registration credential from`,
		"Delivery through Identity QR (Claim 169).", "Full Name", "Wanjiku Njeri", "Date of Birth", "Gender", "Female",
		`href="/issuance/pdf/ref-169"`, "Download the PDF", "Delivered",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("result lacks %q", want)
		}
	}
	if strings.Contains(doc, "Offer link") || strings.Contains(doc, "Open in a wallet") {
		t.Error("an identity QR has no offer link")
	}
	// A code the page cannot read still shows, without the attribute list.
	h.issuance.next = &issuancev1.Offer{Id: "offer-170", Channel: backendv1.Channel_CHANNEL_CLAIM169_QR,
		State: issuancev1.Offer_STATE_DELIVERED, IdentityQr: "NCF broken", PdfRef: "ref-170"}
	h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_CLAIM169_QR"))
	doc = body(t, h.get(t, "/issue/offers/offer-170"))
	a11ytest.AssertPage(t, doc)
	if strings.Contains(doc, "Date of Birth") || !strings.Contains(doc, "Identity QR code ready") {
		t.Error("a broken code shows attributes")
	}
}
