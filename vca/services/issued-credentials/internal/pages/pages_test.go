// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestIssuedListSearch covers the search and the three filters of the
// list: schema, status, and the date range. Each view passes the
// accessibility checks.
func TestIssuedListSearch(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/issued/"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		msg.T("issuer.issued.lead"), msg.T("issuer.issued.search.hint"), `class="field-row"`, `<form method="get" action="/issued/">`,
		msg.T("issuer.issued.schema.any.label"), `<option value="nurse-licence">`, msg.T("issuer.issued.status.any.label"),
		`type="date"`, msg.T("issuer.issued.export.csv.label"), msg.T("issuer.issued.export.json.label"),
		"Wanjiku Njeri", "Farmer v2", "20 Sep 2026", msg.T("issuer.issued.status.active.label"),
		msg.T("issuer.issued.caption.label", "3", "3"), `aria-current="page"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	if !listed(doc, recWanjiku) || !listed(doc, recOtieno) || !listed(doc, recAmina) {
		t.Fatal("the list lacks a record")
	}
	if strings.Index(doc, recWanjiku) > strings.Index(doc, recAmina) {
		t.Error("the newest record does not come first")
	}
	cases := []struct {
		query string
		want  []string
	}{
		{"q=wanjiku", []string{recWanjiku}},
		{"q=FM-0043", []string{recOtieno}},
		{"schema=nurse-licence", []string{recAmina}},
		{"from=2026-09-15", []string{recWanjiku}},
		{"to=2026-08-01", []string{recAmina}},
		{"from=2026-09-01&to=2026-09-12&schema=farmer", []string{recOtieno}},
		{"status=revoked", nil},
	}
	for _, c := range cases {
		view := body(t, h.get(t, "/issued/?"+c.query))
		a11ytest.AssertPage(t, view)
		for _, id := range []string{recWanjiku, recOtieno, recAmina} {
			want := false
			for _, w := range c.want {
				want = want || w == id
			}
			if listed(view, id) != want {
				t.Errorf("%s: record %s listed %v, want %v", c.query, id, !want, want)
			}
		}
		if len(c.want) == 0 && !strings.Contains(view, msg.T("issuer.issued.none")) {
			t.Errorf("%s: the empty table says nothing", c.query)
		}
	}
	// The export buttons carry the search and the filters of the page.
	doc = body(t, h.get(t, "/issued/?q=wanjiku&schema=farmer"))
	if !strings.Contains(doc, `href="/issued/export.csv?q=wanjiku&amp;schema=farmer"`) {
		t.Error("the export button drops the filters")
	}
	// A date that does not parse filters nothing and names the field.
	doc = body(t, h.get(t, "/issued/?from=25/09/2026"))
	if !strings.Contains(doc, msg.T("issuer.issued.date.error")) || !strings.Contains(doc, `aria-invalid="true"`) || !listed(doc, recAmina) {
		t.Error("a bad date is not reported on its field")
	}
	// htmx gets the page partial.
	r := httptest.NewRequest(http.MethodGet, "/issued/?q=wanjiku", nil)
	r.Header.Set("HX-Request", "true")
	a11ytest.AssertFragment(t, body(t, h.do(t, r)))
}

// TestIssuedListPages pages through a long log with a next and a first
// page link.
func TestIssuedListPages(t *testing.T) {
	h := newHarness(t)
	h.opts.PageSize = 2
	h.build(t)
	doc := body(t, h.get(t, "/issued/?schema=farmer&page=0"))
	if !listed(doc, recWanjiku) || !listed(doc, recOtieno) || listed(doc, recAmina) {
		t.Fatal("the first page is wrong")
	}
	doc = body(t, h.get(t, "/issued/"))
	if !strings.Contains(doc, `href="/issued/?page=2"`) || !strings.Contains(doc, msg.T("issuer.issued.next.label")) {
		t.Fatal("the first page has no next link")
	}
	doc = body(t, h.get(t, "/issued/?page=2"))
	if !listed(doc, recAmina) || listed(doc, recWanjiku) || !strings.Contains(doc, msg.T("issuer.issued.first.label")) {
		t.Fatal("the second page is wrong")
	}
	if rec := h.get(t, "/issued/?page=x"); rec.Code != http.StatusBadRequest {
		t.Fatalf("a bad page token gives %d", rec.Code)
	}
}

// TestIssuedListEmptyState points an empty log at the issue wizard.
func TestIssuedListEmptyState(t *testing.T) {
	h := newEmptyHarness(t)
	doc := body(t, h.get(t, "/issued/"))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, msg.T("issuer.issued.empty.title")) || !strings.Contains(doc, `href="/issue/"`) {
		t.Fatal("the empty log has no way to issue")
	}
}

// TestDetailShowsHistory shows the stored fields with the data
// minimisation sentence (ADR-017 decision 2), the record, and the
// history from the audit log of the service with the actor of each
// change.
func TestDetailShowsHistory(t *testing.T) {
	h := newHarness(t)
	if rec := h.post(t, "/issued/"+recWanjiku+"/suspend", url.Values{"reason": {"The cooperative asked for a review."}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("suspend: %d %s", rec.Code, rec.Body.String())
	}
	doc := body(t, h.get(t, "/issued/"+recWanjiku))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"VCA stores only the fields you mark as searchable.",
		"fullName", "Wanjiku Njeri", "farmerID", "FM-0042",
		msg.T("issuer.issued.history.label"), msg.T("issuer.issued.event.issued.label"), "20 Sep 2026",
		msg.T("issuer.issued.event.suspend.label"), "kc|wanjiru", msg.T("audit.issued.status", "suspended"),
		"The cooperative asked for a review.", "list-1", recWanjiku,
		msg.T("issuer.issued.action.reinstate.label"), msg.T("issuer.issued.action.revoke.label"),
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the detail lacks %q", want)
		}
	}
	if strings.Contains(doc, `>`+msg.T("issuer.issued.action.suspend.label")+`<`) {
		t.Error("a suspended credential offers a suspend")
	}
	if rec := h.get(t, "/issued/no-such-record"); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown record gives %d", rec.Code)
	}
}

// TestRevokeNeedsReasonAndCSRF opens the reason dialog with the
// synchronizer token, refuses an empty reason on its field, refuses a
// viewer, and refuses a POST without the token at the guard.
func TestRevokeNeedsReasonAndCSRF(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/issued/"+recWanjiku+"?action=revoke"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<dialog id="status-dialog"`, " open>", msg.T("issuer.issued.dialog.revoke.label"), msg.T("issuer.issued.dialog.revoke.text"),
		`action="/issued/` + recWanjiku + `/revoke"`, `name="` + staffsession.Field + `" value="csrf-1"`,
		`<textarea id="reason" name="reason" required`, msg.T("issuer.issued.confirm.revoke.label"),
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the dialog lacks %q", want)
		}
	}
	rec := h.post(t, "/issued/"+recWanjiku+"/revoke", url.Values{"reason": {"  "}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an empty reason gives %d", rec.Code)
	}
	doc = rec.Body.String()
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, msg.T("issuer.issued.reason.error")) || !strings.Contains(doc, `aria-invalid="true"`) || !strings.Contains(doc, " open>") {
		t.Error("the empty reason is not on its field")
	}
	if len(h.status.calls) != 0 {
		t.Fatal("an empty reason reached the status service")
	}

	h.sess = viewer
	if rec := h.post(t, "/issued/"+recWanjiku+"/revoke", url.Values{"reason": {"Fraud"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("a viewer revoke gives %d", rec.Code)
	}
	doc = body(t, h.get(t, "/issued/"+recWanjiku+"?action=revoke"))
	if strings.Contains(doc, "<dialog") || strings.Contains(doc, msg.T("issuer.issued.action.revoke.label")+"<") {
		t.Error("a viewer sees a status action")
	}
	if !strings.Contains(doc, msg.T("issuer.issued.role.text")) {
		t.Error("a viewer is not told why")
	}
	if len(h.status.calls) != 0 {
		t.Fatal("a viewer changed a status")
	}

	// Behind the guard, a POST without the token never reaches the page.
	iss := staffsessiontest.New(t, staffsession.IssuerAudience, time.Now())
	guard, err := staffsession.New(staffsession.Options{Keys: iss.Keys(), Audience: staffsession.IssuerAudience, Cookie: staffsession.IssuerCookie})
	if err != nil {
		t.Fatal(err)
	}
	token := iss.Token(t, "kc|wanjiru", staffsession.IssuerOperatorRole)
	guarded := guard.Wrap(h.mux)
	r := httptest.NewRequest(http.MethodPost, "/issued/"+recWanjiku+"/revoke", strings.NewReader("reason=Fraud"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(iss.Cookie(staffsession.IssuerCookie, token))
	w := httptest.NewRecorder()
	guarded.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || len(h.status.calls) != 0 {
		t.Fatalf("a POST without the token gives %d", w.Code)
	}
}

// TestSuspendThenReinstate runs a suspension and its end through the
// status service of VCA, with a notice after each change.
func TestSuspendThenReinstate(t *testing.T) {
	h := newHarness(t)
	rec := h.post(t, "/issued/"+recOtieno+"/suspend", url.Values{"reason": {"Review"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/issued/"+recOtieno+"?notice=suspended" {
		t.Fatalf("suspend: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	doc := body(t, h.get(t, rec.Header().Get("Location")))
	if !strings.Contains(doc, msg.T("issuer.issued.notice.suspended")) || !strings.Contains(doc, msg.T("issuer.issued.status.suspended.label")) {
		t.Fatal("the detail does not show the suspension")
	}
	rec = h.post(t, "/issued/"+recOtieno+"/reinstate", url.Values{"reason": {"Cleared"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reinstate: %d %s", rec.Code, rec.Body.String())
	}
	if len(h.status.calls) != 2 || h.status.calls[0].GetValue() != service.StatusValueSet || h.status.calls[1].GetValue() != service.StatusValueClear {
		t.Fatalf("status calls = %v", h.status.calls)
	}
	doc = body(t, h.get(t, "/issued/"+recOtieno+"?notice=reinstated"))
	if !strings.Contains(doc, msg.T("issuer.issued.notice.reinstated")) || !strings.Contains(doc, msg.T("issuer.issued.event.reinstate.label")) {
		t.Fatal("the detail does not show the reinstatement")
	}
	// A reinstate of an active credential fails with a sentence.
	rec = h.post(t, "/issued/"+recOtieno+"/reinstate", url.Values{"reason": {"Again"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), msg.T("issuer.issued.failed.precondition")) {
		t.Fatalf("a second reinstate: %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	if rec := h.post(t, "/issued/"+recOtieno+"/delete", url.Values{"reason": {"x"}}); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("an unknown action gives %d", rec.Code)
	}
}

// TestExportCSV exports the rows of the page as CSV with a formula
// guard, and as JSON lines. Each export leaves an audit event with the
// actor.
func TestExportCSV(t *testing.T) {
	h := newHarness(t)
	rec := h.get(t, "/issued/export.csv?schema=farmer")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), `attachment; filename="issued-credentials.csv"`) {
		t.Fatalf("csv: %d %v", rec.Code, rec.Header())
	}
	rows, err := csv.NewReader(bytes.NewReader(rec.Body.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("csv rows = %d, want the header and two farmers", len(rows))
	}
	if !strings.Contains(rec.Body.String(), "'=Otieno Ouma") {
		t.Error("the CSV export has no formula guard")
	}
	rec = h.get(t, "/issued/export.json?q=amina")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-ndjson" ||
		strings.Count(rec.Body.String(), "\n") != 1 || !strings.Contains(rec.Body.String(), recAmina) {
		t.Fatalf("json: %d %q", rec.Code, rec.Body.String())
	}
	page, err := h.svc.Audit().Query(context.Background(), auditlog.Filter{Action: service.ActionExport})
	if err != nil || len(page.Records) != 2 || page.Records[0].Actor != operator.Subject {
		t.Fatalf("export events = %+v, %v", page.Records, err)
	}
	if rec := h.get(t, "/issued/export.csv?q="+strings.Repeat("x", 201)); rec.Code != http.StatusBadRequest {
		t.Fatalf("a long query gives %d", rec.Code)
	}
}

// TestDpgRevokeUsedWhenListed sends the revoke of a record from the
// stack ledger to the stack when its adapter lists FEATURE_REVOCATION,
// and every other revoke to the status service of VCA. The dialog names
// the path.
func TestDpgRevokeUsedWhenListed(t *testing.T) {
	h := newHarness(t, backendv1.Feature_FEATURE_REVOCATION)
	doc := body(t, h.get(t, "/issued/"+recWanjiku+"?action=revoke"))
	if !strings.Contains(doc, msg.T("issuer.issued.dialog.revoke.stack", stackName)) {
		t.Error("the dialog does not name the stack")
	}
	if rec := h.post(t, "/issued/"+recWanjiku+"/revoke", url.Values{"reason": {"Lost card"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if len(h.stack.revokes) != 1 || len(h.status.calls) != 0 {
		t.Fatalf("stack %d, status %d", len(h.stack.revokes), len(h.status.calls))
	}
	doc = body(t, h.get(t, "/issued/"+recWanjiku))
	if !strings.Contains(doc, msg.T("audit.issued.stack", "revoked")) || strings.Contains(doc, msg.T("issuer.issued.action.reinstate.label")+"<") {
		t.Error("the history does not name the stack, or a revoked credential offers an action")
	}
	// A record with a status entry of VCA stays with the status service.
	doc = body(t, h.get(t, "/issued/"+recOtieno+"?action=revoke"))
	if strings.Contains(doc, msg.T("issuer.issued.dialog.revoke.stack", stackName)) {
		t.Error("the dialog of a record with a VCA status entry names the stack")
	}
	if rec := h.post(t, "/issued/"+recOtieno+"/revoke", url.Values{"reason": {"Fraud"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if len(h.stack.revokes) != 1 || len(h.status.calls) != 1 {
		t.Fatalf("stack %d, status %d", len(h.stack.revokes), len(h.status.calls))
	}

	plain := newHarness(t)
	if rec := plain.post(t, "/issued/"+recWanjiku+"/revoke", url.Values{"reason": {"Lost card"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if len(plain.stack.revokes) != 0 || len(plain.status.calls) != 1 {
		t.Fatalf("stack %d, status %d", len(plain.stack.revokes), len(plain.status.calls))
	}
}

// TestOfferedNotClaimedOnlyWithFeature shows the state "Offered, not
// claimed" only when the adapter lists FEATURE_ISSUANCE_STATUS, and asks
// the adapter with its own offer id.
func TestOfferedNotClaimedOnlyWithFeature(t *testing.T) {
	h := newHarness(t)
	h.stack.pending["dpg-offer-1"] = true
	doc := body(t, h.get(t, "/issued/"))
	if strings.Contains(doc, msg.T("issuer.issued.status.offered.label")) || len(h.stack.asked) != 0 {
		t.Fatal("the offer state shows without the feature")
	}
	h = newHarness(t, backendv1.Feature_FEATURE_ISSUANCE_STATUS)
	h.stack.pending["dpg-offer-1"] = true
	doc = body(t, h.get(t, "/issued/"))
	if strings.Count(doc, msg.T("issuer.issued.status.offered.label")) != 1 {
		t.Fatal("the unclaimed offer does not show")
	}
	if strings.Join(h.stack.asked, ",") != "dpg-offer-1,dpg-offer-2" {
		t.Fatalf("asked %v", h.stack.asked)
	}
	doc = body(t, h.get(t, "/issued/"+recWanjiku))
	if !strings.Contains(doc, msg.T("issuer.issued.status.offered.label")) {
		t.Fatal("the detail does not show the unclaimed offer")
	}
}

// TestActionsSendTheActor names the staff member in every audit event
// of a change made on the pages.
func TestActionsSendTheActor(t *testing.T) {
	h := newHarness(t)
	for _, step := range []struct{ path, reason string }{
		{"/issued/" + recAmina + "/suspend", "Review"},
		{"/issued/" + recAmina + "/reinstate", "Cleared"},
		{"/issued/" + recAmina + "/revoke", "Lost"},
	} {
		if rec := h.post(t, step.path, url.Values{"reason": {step.reason}}); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d", step.path, rec.Code)
		}
	}
	events, err := h.svc.History(context.Background(), recAmina)
	if err != nil || len(events) != 3 {
		t.Fatalf("history = %+v, %v", events, err)
	}
	for _, e := range events {
		if e.Actor != operator.Subject || !e.OK {
			t.Errorf("event %+v", e)
		}
	}
	got, err := h.svc.Get(context.Background(), connectReq(recAmina))
	if err != nil || got.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_REVOKED {
		t.Fatalf("record = %v, %v", got, err)
	}
}

// TestNewChecksItsOptions refuses pages without the parts they draw on.
func TestNewChecksItsOptions(t *testing.T) {
	h := newHarness(t)
	for name, edit := range map[string]func(*pages.Options){
		"kit":     func(o *pages.Options) { o.Kit = nil },
		"shell":   func(o *pages.Options) { o.Shell = nil },
		"records": func(o *pages.Options) { o.Records = nil },
	} {
		o := h.opts
		edit(&o)
		if _, err := pages.New(o); err == nil {
			t.Errorf("no %s passes", name)
		}
	}
	o := h.opts
	o.Stack, o.SignOut = nil, nil
	p, err := pages.New(o)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	r := httptest.NewRequest(http.MethodGet, "/issued/"+recWanjiku+"?action=revoke", nil)
	r = r.WithContext(staffsession.With(r.Context(), operator))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), msg.T("issuer.issued.dialog.revoke.text")) {
		t.Fatalf("no stack: %d", w.Code)
	}
}

// TestSignOutEndsTheSession passes the sign out form to the handler of
// the shell.
func TestSignOutEndsTheSession(t *testing.T) {
	h := newHarness(t)
	if rec := h.post(t, pages.SignOutPath, url.Values{}); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign out gives %d", rec.Code)
	}
}

// connectReq is a Get request for one record.
func connectReq(id string) *connect.Request[issuedv1.GetRequest] {
	return connect.NewRequest(&issuedv1.GetRequest{Id: id})
}

// ledger returns two entries of the stack ledger.
func ledger() []*backendv1.LedgerEntry {
	entry := func(id string, index int64, day int) *backendv1.LedgerEntry {
		return &backendv1.LedgerEntry{
			CredentialId: id, CredentialType: "FarmerCredential,VerifiableCredential", StatusPurpose: "revocation",
			IssuedAt: timestamppb.New(fixedNow.AddDate(0, 0, day)),
			Status: &backendv1.StatusListBinding{Kind: backendv1.StatusListBinding_KIND_BITSTRING,
				ListId: "https://stack.example/status/1", Index: index, PublishUrl: "https://stack.example/status/1"},
		}
	}
	return []*backendv1.LedgerEntry{entry("urn:uuid:wanjiku", 9, -5), entry("urn:uuid:new", 17, -1)}
}

// TestIssuedSyncOnlyWithFeature offers "Sync from stack" only when the
// adapter lists FEATURE_ISSUED_LEDGER. The sync adds the entries the log
// lacks and says what it did with each one.
func TestIssuedSyncOnlyWithFeature(t *testing.T) {
	plain := newHarness(t)
	if strings.Contains(body(t, plain.get(t, "/issued/")), `href="/issued/sync"`) {
		t.Fatal("the list offers a sync without the feature")
	}
	if rec := plain.get(t, "/issued/sync"); rec.Code != http.StatusNotFound {
		t.Fatalf("the sync page answers %d without the feature", rec.Code)
	}
	if rec := plain.post(t, "/issued/sync", url.Values{"type": {"FarmerCredential"}}); rec.Code != http.StatusNotFound {
		t.Fatalf("the sync form answers %d without the feature", rec.Code)
	}

	h := newHarness(t, backendv1.Feature_FEATURE_ISSUED_LEDGER, backendv1.Feature_FEATURE_REVOCATION)
	h.stack.ledger = ledger()
	list := body(t, h.get(t, "/issued/"))
	if !strings.Contains(list, `href="/issued/sync"`) || !strings.Contains(list, msg.T("issuer.issued.sync.action.label")) {
		t.Fatal("the list does not offer the sync")
	}
	form := body(t, h.get(t, "/issued/sync"))
	a11ytest.AssertPage(t, form)
	for _, want := range []string{`name="type"`, `name="attribute"`, `name="value"`, `name="csrf_token"`, msg.T("issuer.issued.sync.submit.label", stackName)} {
		if !strings.Contains(form, want) {
			t.Errorf("the sync page lacks %q", want)
		}
	}
	rec := h.post(t, "/issued/sync", url.Values{"type": {"FarmerCredential"}})
	missing := rec.Body.String()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a missing field gives %d", rec.Code)
	}
	a11ytest.AssertPage(t, missing)
	if !strings.Contains(missing, msg.T("issuer.issued.sync.required")) || !strings.Contains(missing, `aria-invalid="true"`) {
		t.Fatal("a missing field has no error")
	}
	done := body(t, h.post(t, "/issued/sync", url.Values{"type": {"FarmerCredential"}, "attribute": {"farmerID"}, "value": {"FM-0042"}}))
	a11ytest.AssertPage(t, done)
	for _, want := range []string{
		msg.T("issuer.issued.sync.notice", "1", "2"), msg.T("issuer.issued.sync.added.label"), msg.T("issuer.issued.sync.kept.label"),
		"urn:uuid:new", `href="/issued/` + recWanjiku + `"`,
	} {
		if !strings.Contains(done, want) {
			t.Errorf("the sync result lacks %q", want)
		}
	}
	if got := body(t, h.get(t, "/issued/")); !strings.Contains(got, "FarmerCredential") {
		t.Error("the added record is not in the list")
	}
	h.stack.ledger = nil
	if none := body(t, h.post(t, "/issued/sync", url.Values{"type": {"Other"}, "attribute": {"farmerID"}, "value": {"FM-9"}})); !strings.Contains(none, msg.T("issuer.issued.sync.none")) {
		t.Error("an empty answer does not say so")
	}
	h.stack.ledgerErr = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if rec := h.post(t, "/issued/sync", url.Values{"type": {"Other"}, "attribute": {"farmerID"}, "value": {"FM-9"}}); rec.Code != http.StatusServiceUnavailable ||
		!strings.Contains(rec.Body.String(), msg.T("issuer.issued.sync.failed")) {
		t.Errorf("a stack failure gives %d without the reason", rec.Code)
	}
	h.stack.ledgerErr = connect.NewError(connect.CodeInvalidArgument, errors.New("bad attribute"))
	if rec := h.post(t, "/issued/sync", url.Values{"type": {"Other"}, "attribute": {"x"}, "value": {"FM-9"}}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), msg.T("issuer.issued.sync.refused")) {
		t.Errorf("a refused search gives %d without the reason", rec.Code)
	}
	h.sess = viewer
	if rec := h.post(t, "/issued/sync", url.Values{"type": {"Other"}, "attribute": {"x"}, "value": {"FM-9"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("a viewer syncs: %d", rec.Code)
	}
}

// TestIssuedListSchemaReadsAsWords is P4-05. The schema column and the
// schema filter name each schema as words. The filter still sends the
// schema id.
func TestIssuedListSchemaReadsAsWords(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/issued/"))
	for _, want := range []string{">Farmer v2<", `<option value="nurse-licence">Nurse licence</option>`, `<option value="farmer">Farmer</option>`} {
		if !strings.Contains(doc, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	if strings.Contains(doc, ">farmer v2<") {
		t.Error("the list shows the schema id")
	}
}
