// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// recLicence is a record whose credential carries an entry of the status
// list of the stack.
const recLicence = "rec-licence"

// seedStackList appends the record of an offer of a stack that keeps its
// own status list.
func (h *harness) seedStackList(t *testing.T) {
	t.Helper()
	if _, err := h.svc.AppendRecord(record.Record{
		ID: recLicence, SchemaID: "trade-licence", SchemaVersion: 1, IssuedAt: fixedNow.AddDate(0, 0, -1),
		SubjectRef: h.svc.SubjectRef(recLicence), Format: "dc+sd-jwt", DPG: "dpg-adapter",
		DPGCredentialID: "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56",
		Binding: record.Binding{Kind: record.KindToken, ListID: "6f1e2d3c", Index: 4211,
			PublishURL: "https://status.issuer.example.org/status-lists/6f1e2d3c", DPGList: true},
	}); err != nil {
		t.Fatal(err)
	}
}

// TestDetailNamesTheListThatHoldsTheStatus: the record page says whether
// the list of the stack or a status service of VCA holds the status.
func TestDetailNamesTheListThatHoldsTheStatus(t *testing.T) {
	h := newHarness(t, backendv1.Feature_FEATURE_REVOCATION)
	h.seedStackList(t)
	doc := body(t, h.get(t, "/issued/"+recLicence))
	a11ytest.AssertPage(t, doc)
	if want := msg.T("issuer.issued.record.holder.stack", stackName); !strings.Contains(doc, want) {
		t.Errorf("the page of an entry of the stack does not say %q", want)
	}
	doc = body(t, h.get(t, "/issued/"+recOtieno))
	if want := msg.T("issuer.issued.record.holder.vca"); !strings.Contains(doc, want) {
		t.Errorf("the page of an entry of VCA does not say %q", want)
	}
}

// TestAStackListRecordOffersOnlyWhatTheStackDoes: no status service of
// VCA can change an entry of the list of the stack. A stack that lists
// revocation only offers a revoke, and one that lists neither change
// offers no action at all.
func TestAStackListRecordOffersOnlyWhatTheStackDoes(t *testing.T) {
	suspend, revoke := "?action=suspend", "?action=revoke"
	h := newHarness(t, backendv1.Feature_FEATURE_REVOCATION)
	h.seedStackList(t)
	doc := body(t, h.get(t, "/issued/"+recLicence))
	if !strings.Contains(doc, revoke) || strings.Contains(doc, suspend) {
		t.Error("a stack that only revokes offers a suspension, or no revocation")
	}
	none := newHarness(t)
	none.seedStackList(t)
	doc = body(t, none.get(t, "/issued/"+recLicence))
	if strings.Contains(doc, revoke) || strings.Contains(doc, suspend) {
		t.Error("a stack that changes nothing still offers an action on an entry of its own list")
	}
}
