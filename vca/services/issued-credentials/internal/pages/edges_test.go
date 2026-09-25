// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestRecordWithoutStatusEntry shows a record that cannot change: no
// status list entry, no searchable field, an ended validity, and an
// unknown format. It offers no action.
func TestRecordWithoutStatusEntry(t *testing.T) {
	h := newEmptyHarness(t)
	r := record.Record{ID: "0badc0de", SchemaID: "visitor", SchemaVersion: 1, IssuedAt: fixedNow.AddDate(0, 0, -40),
		ValidUntil: fixedNow.AddDate(0, 0, -1), Format: "not-a-format", Hash: "abc123"}
	r.SubjectRef = h.svc.SubjectRef("visitor-1")
	if _, err := h.svc.AppendRecord(r); err != nil {
		t.Fatal(err)
	}
	list := body(t, h.get(t, "/issued/"))
	if !strings.Contains(list, msg.T("issuer.issued.status.expired.label")) || !strings.Contains(list, r.SubjectRef[:8]) {
		t.Fatal("the expired record without fields does not show")
	}
	doc := body(t, h.get(t, "/issued/0badc0de?action=revoke"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		msg.T("issuer.issued.record.no_status_list"), msg.T("issuer.issued.fields.none"), msg.T("common.unknown.label"),
		"16 Aug 2026", "24 Sep 2026", "abc123",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the detail lacks %q", want)
		}
	}
	if strings.Contains(doc, "<dialog") || strings.Contains(doc, msg.T("issuer.issued.action.revoke.label")+"<") {
		t.Error("a record without a status entry offers an action")
	}
}

// TestStatusServiceDownShowsOnTheRecord keeps the record and names the
// problem when the status service does not answer.
func TestStatusServiceDownShowsOnTheRecord(t *testing.T) {
	h := newHarness(t)
	h.status.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	rec := h.post(t, "/issued/"+recWanjiku+"/suspend", url.Values{"reason": {"Review"}})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), msg.T("issuer.issued.failed.unavailable")) {
		t.Fatalf("status %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	if rec := h.post(t, "/issued/no-such-record/revoke", url.Values{"reason": {"x"}}); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown record gives %d", rec.Code)
	}
	if rec := h.post(t, "/issued/"+recWanjiku+"/archive", url.Values{"reason": {"x"}}); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown action gives %d", rec.Code)
	}
}

// TestStackWithoutNameUsesThisStack keeps the dialog readable when the
// adapter reports no name.
func TestStackWithoutNameUsesThisStack(t *testing.T) {
	h := newHarness(t, backendv1.Feature_FEATURE_REVOCATION)
	h.stack.name = ""
	doc := body(t, h.get(t, "/issued/"+recWanjiku+"?action=revoke"))
	if !strings.Contains(doc, msg.T("issuer.issued.dialog.revoke.stack", msg.T("issuer.stack.this.label"))) {
		t.Fatal("the dialog does not fall back to this stack")
	}
}

// TestAdminActsAndHistoryNamesNoActor lets an issuer admin act, and
// names a change without an actor as such.
func TestAdminActsAndHistoryNamesNoActor(t *testing.T) {
	h := newHarness(t)
	h.sess = operator
	h.sess.Roles = []string{"issuer-admin"}
	h.sess.Subject = ""
	if rec := h.post(t, "/issued/"+recAmina+"/revoke", url.Values{"reason": {"Fraud"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("admin revoke: %d", rec.Code)
	}
	doc := body(t, h.get(t, "/issued/"+recAmina))
	if strings.Count(doc, msg.T("issuer.issued.actor.none.label")) != 2 {
		t.Fatal("the history does not say that no actor was named")
	}
}
