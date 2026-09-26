// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// P6-C3 and ADR-059: the delivery step shows a DIDComm invitation card
// and an email card when the adapter lists those channels, and each
// card only for a schema format the channel carries.

// fakeConnections answers the DIDComm connections of the adapter.
type fakeConnections struct {
	list []*backendv1.DidcommConnection
	err  error
}

func (f *fakeConnections) ListConnections(context.Context, *connect.Request[backendv1.ListConnectionsRequest]) (*connect.Response[backendv1.ListConnectionsResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&backendv1.ListConnectionsResponse{Connections: f.list}), nil
}

// didcommCaps is the answer of a stack that issues SD-JWT over OID4VCI,
// and AnonCreds and JSON-LD over DIDComm, with or without mail.
func didcommCaps(mail bool) *backendv1.GetCapabilitiesResponse {
	caps := issuerCaps(waltidName)
	sdJwt := []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT}
	didcomm := []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}
	caps.Formats = append(append([]commonv1.Format(nil), sdJwt...), didcomm...)
	caps.Channels = []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, backendv1.Channel_CHANNEL_DIDCOMM_OOB}
	caps.ChannelFormats = []*backendv1.ChannelFormats{
		{Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, Formats: sdJwt},
		{Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB, Formats: didcomm},
	}
	if mail {
		caps.Channels = append(caps.Channels, backendv1.Channel_CHANNEL_EMAIL)
		caps.ChannelFormats = append(caps.ChannelFormats, &backendv1.ChannelFormats{Channel: backendv1.Channel_CHANNEL_EMAIL, Formats: didcomm})
	}
	return caps
}

// didcommFarmer is the farmer schema published as SD-JWT and AnonCreds.
func didcommFarmer(formats ...commonv1.Format) *schemav1.Schema {
	s := farmer()
	s.Formats = formats
	return s
}

func didcommHarness(t *testing.T, mail bool, formats ...commonv1.Format) (*harness, *fakeConnections) {
	t.Helper()
	h := newHarness(t)
	h.caps.caps = didcommCaps(mail)
	h.snap.Peers[0].Capabilities = h.caps.caps
	h.schemas.published = []*schemav1.Schema{didcommFarmer(formats...)}
	conns := &fakeConnections{list: []*backendv1.DidcommConnection{
		{Id: "conn-1", Label: "Wanjiku wallet", State: "completed", CreatedAt: timestamppb.New(time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC))},
		{Id: "conn-2", Label: "", State: "request-received"},
	}}
	h.opts.Connections = conns
	h.build(t)
	return h, conns
}

// TestDeliveryCardsFollowTheDidcommChannels is P6-C3: the cards come
// from the channels of the adapter, each for a format it carries.
func TestDeliveryCardsFollowTheDidcommChannels(t *testing.T) {
	h, conns := didcommHarness(t, true, commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_ANONCREDS)
	doc := body(t, h.post(t, "/issue/delivery", goodClaims()))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"CHANNEL_OID4VCI_PREAUTH", "CHANNEL_DIDCOMM_OOB", "CHANNEL_EMAIL", "DIDComm invitation", "Email from the stack",
		`<select id="connection" name="connection"`, `<option value="conn-1">Wanjiku wallet</option>`,
		`<input type="email" id="holder_email" name="holder_email"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("delivery lacks %q", want)
		}
	}
	// A connection that is not complete takes no offer.
	if strings.Contains(doc, "conn-2") {
		t.Error("the page offers a connection that is not complete")
	}
	// A schema published only as AnonCreds goes over DIDComm alone.
	h.schemas.published = []*schemav1.Schema{didcommFarmer(commonv1.Format_FORMAT_ANONCREDS)}
	doc = body(t, h.post(t, "/issue/delivery", goodClaims()))
	for _, gone := range []string{`value="CHANNEL_OID4VCI_PREAUTH"`, `value="CHANNEL_DC_API"`, `value="CHANNEL_PDF"`} {
		if strings.Contains(doc, gone) {
			t.Errorf("an AnonCreds schema offers %s", gone)
		}
	}
	if !strings.Contains(doc, `value="CHANNEL_DIDCOMM_OOB"`) {
		t.Error("an AnonCreds schema has no DIDComm card")
	}
	// A schema without a DIDComm format gets no DIDComm card.
	h.schemas.published = []*schemav1.Schema{didcommFarmer(commonv1.Format_FORMAT_DC_SD_JWT)}
	doc = body(t, h.post(t, "/issue/delivery", goodClaims()))
	if strings.Contains(doc, `value="CHANNEL_DIDCOMM_OOB"`) || strings.Contains(doc, `value="CHANNEL_EMAIL"`) {
		t.Error("an SD-JWT schema offers a DIDComm card")
	}
	// No connection list: no select, the invitation stays.
	h.schemas.published = []*schemav1.Schema{didcommFarmer(commonv1.Format_FORMAT_ANONCREDS)}
	conns.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	doc = body(t, h.post(t, "/issue/delivery", goodClaims()))
	if strings.Contains(doc, `id="connection"`) || !strings.Contains(doc, `value="CHANNEL_DIDCOMM_OOB"`) {
		t.Error("a failed connection list breaks the DIDComm card")
	}
}

// TestChannelsListed is P6-C3 for the pages: a stack without DIDComm,
// or without mail, shows none of those cards.
func TestChannelsListed(t *testing.T) {
	h, _ := didcommHarness(t, false, commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_ANONCREDS)
	doc := body(t, h.post(t, "/issue/delivery", goodClaims()))
	if strings.Contains(doc, `value="CHANNEL_EMAIL"`) || !strings.Contains(doc, `value="CHANNEL_DIDCOMM_OOB"`) {
		t.Error("the email card shows without mail")
	}
	plain := newHarness(t)
	plain.schemas.published = []*schemav1.Schema{farmer()}
	doc = body(t, plain.post(t, "/issue/delivery", goodClaims()))
	if strings.Contains(doc, "CHANNEL_DIDCOMM_OOB") || strings.Contains(doc, "CHANNEL_EMAIL") || strings.Contains(doc, `id="connection"`) {
		t.Error("a stack without DIDComm shows a DIDComm card")
	}
}

// TestIssueOverDidcommFromTheWizard: the review names the connection,
// and the issue request carries it with the channel.
func TestIssueOverDidcommFromTheWizard(t *testing.T) {
	h, _ := didcommHarness(t, true, commonv1.Format_FORMAT_ANONCREDS)
	form := with(goodClaims(), "channel", "CHANNEL_DIDCOMM_OOB", "connection", "conn-1")
	doc := body(t, h.post(t, "/issue/review", form))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Review" || !strings.Contains(doc, "Wanjiku wallet") || !strings.Contains(doc, `name="connection" value="conn-1"`) {
		t.Errorf("review lacks the connection\n%s", doc)
	}
	if rec := h.post(t, "/issue/offers", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	d := h.issuance.requests[0].GetDelivery()
	if d.GetChannel() != backendv1.Channel_CHANNEL_DIDCOMM_OOB || d.GetConnectionId() != "conn-1" {
		t.Errorf("delivery = %v", d)
	}
	// Without a connection the stack makes a new invitation.
	doc = body(t, h.post(t, "/issue/review", with(goodClaims(), "channel", "CHANNEL_DIDCOMM_OOB")))
	if !strings.Contains(doc, "A new invitation") {
		t.Error("the review does not name the new invitation")
	}
}

// TestEmailChannelNeedsAnAddress: the email card needs the address of
// the holder, which the review shows and the request carries.
func TestEmailChannelNeedsAnAddress(t *testing.T) {
	h, _ := didcommHarness(t, true, commonv1.Format_FORMAT_ANONCREDS)
	doc := body(t, h.post(t, "/issue/review", with(goodClaims(), "channel", "CHANNEL_EMAIL", "holder_email", "not an address")))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Delivery" || !strings.Contains(doc, "Type the email address of the holder.") {
		t.Errorf("a bad address passes\n%s", doc)
	}
	form := with(goodClaims(), "channel", "CHANNEL_EMAIL", "holder_email", "wanjiku@registry.gov.test")
	doc = body(t, h.post(t, "/issue/review", form))
	if currentStep(t, doc) != "Review" || !strings.Contains(doc, "wanjiku@registry.gov.test") {
		t.Errorf("review lacks the address\n%s", doc)
	}
	h.issuance.next = &issuancev1.Offer{Id: "offer-9", State: issuancev1.Offer_STATE_DELIVERED}
	if rec := h.post(t, "/issue/offers", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if got := h.issuance.requests[0].GetDelivery().GetEmail(); got != "wanjiku@registry.gov.test" {
		t.Errorf("email = %q", got)
	}
	doc = body(t, h.get(t, "/issue/offers/offer-9"))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "The stack mailed the offer to the holder.") || strings.Contains(doc, `class="qr"`) {
		t.Errorf("the result of a mailed offer\n%s", doc)
	}
}

// TestResultShowsTheDidcommInvitation: the result shows the QR code and
// the address of the invitation.
func TestResultShowsTheDidcommInvitation(t *testing.T) {
	h, _ := didcommHarness(t, false, commonv1.Format_FORMAT_ANONCREDS)
	invitation := "https://agent.registry.gov.test?oob=eyJAdHlwZSI6Im91dC1vZi1iYW5kIn0"
	h.issuance.next = &issuancev1.Offer{Id: "offer-8", State: issuancev1.Offer_STATE_PENDING, OfferUri: invitation}
	if rec := h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_DIDCOMM_OOB")); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	doc := body(t, h.get(t, "/issue/offers/offer-8"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{`class="qr"`, "<code>" + invitation + "</code>", "Delivery through DIDComm invitation.", "A DIDComm wallet"} {
		if !strings.Contains(doc, want) {
			t.Errorf("result lacks %q", want)
		}
	}
}
