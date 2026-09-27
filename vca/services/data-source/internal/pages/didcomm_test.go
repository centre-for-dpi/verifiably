// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// A row by row run of an AnonCreds or a JSON-LD schema goes out on the
// DIDComm channels of the stack (ADR-059 decision 5): an invitation per
// row, or an email per row from the stack.

// didcommHarness is a harness whose adapter carries SD-JWT over OID4VCI
// and AnonCreds and JSON-LD over DIDComm and email, with an AnonCreds
// schema.
func didcommHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	caps := issuerCaps()
	caps.Formats = []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}
	caps.Channels = []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, backendv1.Channel_CHANNEL_DIDCOMM_OOB, backendv1.Channel_CHANNEL_EMAIL}
	didcomm := []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}
	caps.ChannelFormats = []*backendv1.ChannelFormats{
		{Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, Formats: []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT}},
		{Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB, Formats: didcomm},
		{Channel: backendv1.Channel_CHANNEL_EMAIL, Formats: didcomm},
	}
	h.schemas.published[0].Formats = []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS}
	h.snap = topology.Snapshot{Peers: []topology.Status{{Peer: h.peers[0], State: topology.Live, Capabilities: caps}}}
	h.build(t)
	return h
}

// TestRunOffersTheDidcommChannels: the run form offers the channels
// that carry the format of the schema, with the column of the address
// for the email channel. OID4VCI does not carry AnonCreds, so the form
// leaves it out.
func TestRunOffersTheDidcommChannels(t *testing.T) {
	h := didcommHarness(t)
	id := h.mapFarmers(t)
	page := body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{
		`value="CHANNEL_DIDCOMM_OOB"`, "DIDComm invitation", `value="CHANNEL_EMAIL"`, "Email from the stack",
		`<select id="email_column" name="email_column"`, `<option value="County">County</option>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the run form lacks %q", want)
		}
	}
	// The document of VCA carries a pre-authorized offer here, and that
	// channel does not carry AnonCreds either.
	for _, absent := range []string{`value="CHANNEL_OID4VCI_PREAUTH"`, `value="CHANNEL_PDF"`} {
		if strings.Contains(page, absent) {
			t.Errorf("the run form offers %s, which does not carry AnonCreds", absent)
		}
	}
	if strings.Index(page, `name="email_column"`) < strings.Index(page, `value="CHANNEL_EMAIL"`) {
		t.Error("the column of the address comes before the channel that needs it")
	}
	rec := h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_DIDCOMM_OOB"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a DIDComm run: %d %s", rec.Code, rec.Body.String())
	}
	h.wait(t)
	req := h.issuance.requests[0]
	if req.GetNative() || req.GetChannel() != backendv1.Channel_CHANNEL_DIDCOMM_OOB || len(req.GetItems()) != 3 || req.GetItems()[0].GetDelivery() != nil {
		t.Fatalf("batch = %v", req)
	}
}

// TestRunMailsEachRowFromTheStack: the email channel needs the column
// of the address, and each row carries its address.
func TestRunMailsEachRowFromTheStack(t *testing.T) {
	h := didcommHarness(t)
	id := h.mapFarmers(t)
	page := body(t, h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_EMAIL"}}))
	if !strings.Contains(page, "Pick the column with the email address of each holder.") {
		t.Errorf("a mail run without the column\n%s", page)
	}
	page = body(t, h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_OID4VCI_PREAUTH"}}))
	if !strings.Contains(page, "Pick one of the delivery channels.") {
		t.Errorf("a channel that does not carry the format\n%s", page)
	}
	rec := h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_EMAIL"}, "email_column": {"County"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a mail run: %d %s", rec.Code, rec.Body.String())
	}
	h.wait(t)
	req := h.issuance.requests[0]
	if req.GetNative() || req.GetChannel() != backendv1.Channel_CHANNEL_EMAIL || len(req.GetItems()) != 3 {
		t.Fatalf("batch = %v", req)
	}
	if d := req.GetItems()[1].GetDelivery(); d.GetChannel() != backendv1.Channel_CHANNEL_EMAIL || d.GetEmail() != "Nyeri" {
		t.Errorf("delivery = %v", d)
	}
}
