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

// P6-C4 and ADR-060: a stack whose bulk import mails each holder an
// offer needs the column with the address of each row.

// mailingHarness is a harness whose adapter lists a bulk import on the
// email channel.
func mailingHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, backendv1.Feature_FEATURE_BULK_NATIVE)
	caps := issuerCaps(backendv1.Feature_FEATURE_BULK_NATIVE)
	caps.BulkImport = &backendv1.BulkImport{
		Channel: backendv1.Channel_CHANNEL_EMAIL, EmailColumn: "email_identifier",
		Formats: []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT},
	}
	h.snap = topology.Snapshot{Peers: []topology.Status{{Peer: h.peers[0], State: topology.Live, Capabilities: caps}}}
	h.build(t)
	return h
}

// TestBulkNativeMailAsksForTheEmailColumn: the run form asks for the
// column of the address, and the batch carries each address.
func TestBulkNativeMailAsksForTheEmailColumn(t *testing.T) {
	h := mailingHarness(t)
	id := h.mapFarmers(t)
	page := body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{
		`value="native"`, "mails each holder an offer", `<select id="email_column" name="email_column"`, `<option value="County">County</option>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the run form lacks %q", want)
		}
	}
	// No column: the run does not start.
	page = body(t, h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "method": {"native"}}))
	if !strings.Contains(page, "Pick the column with the email address of each holder.") {
		t.Errorf("a run without the column\n%s", page)
	}
	rec := h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "method": {"native"}, "email_column": {"County"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	h.wait(t)
	req := h.issuance.requests[0]
	if !req.GetNative() || req.GetChannel() != backendv1.Channel_CHANNEL_EMAIL || len(req.GetItems()) != 3 {
		t.Fatalf("batch = %v", req)
	}
	if d := req.GetItems()[1].GetDelivery(); d.GetChannel() != backendv1.Channel_CHANNEL_EMAIL || d.GetEmail() != "Nyeri" {
		t.Errorf("delivery = %v", d)
	}
}
