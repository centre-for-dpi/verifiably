package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// ledgerSubjects is a SubjectProvisioner exposing only the two ledger reads
// (any other call panics through the nil embedded interface).
type ledgerSubjects struct {
	SubjectProvisioner
	myCreds    []map[string]string
	myCredsErr error
	ledger     []map[string]string
	ledgerErr  error
	ledgerKeys [][]string // keys passed to ListLedger, per call
}

func (f *ledgerSubjects) ListMyCredentials(context.Context, string) ([]map[string]string, error) {
	return f.myCreds, f.myCredsErr
}
func (f *ledgerSubjects) ListLedger(_ context.Context, keys []string) ([]map[string]string, error) {
	f.ledgerKeys = append(f.ledgerKeys, keys)
	return f.ledger, f.ledgerErr
}

// ledgerFakeLog is an issuance.Backend with injectable failures.
type ledgerFakeLog struct {
	items      map[string]issuance.IssuedCredential
	appended   []issuance.IssuedCredential
	appendErr  error
	markErr    error
	revoked    []string
	reinstated []string
	listItems  []issuance.IssuedCredential // returned by List (owner-filtered)
}

func newLedgerFakeLog() *ledgerFakeLog {
	return &ledgerFakeLog{items: map[string]issuance.IssuedCredential{}}
}
func (l *ledgerFakeLog) Append(c issuance.IssuedCredential) (issuance.IssuedCredential, error) {
	if l.appendErr != nil {
		return issuance.IssuedCredential{}, l.appendErr
	}
	l.appended = append(l.appended, c)
	l.items[c.ID] = c
	return c, nil
}
func (l *ledgerFakeLog) Get(id string) (issuance.IssuedCredential, bool) {
	c, ok := l.items[id]
	return c, ok
}
func (l *ledgerFakeLog) List(f issuance.Filter) []issuance.IssuedCredential {
	out := []issuance.IssuedCredential{}
	for _, c := range l.listItems {
		if f.OwnerKey == "" || c.OwnerKey == f.OwnerKey {
			out = append(out, c)
		}
	}
	return out
}
func (l *ledgerFakeLog) Summary() issuance.Stats { return issuance.Stats{} }
func (l *ledgerFakeLog) MarkRevoked(id, _ string) (issuance.IssuedCredential, error) {
	if l.markErr != nil {
		return issuance.IssuedCredential{}, l.markErr
	}
	l.revoked = append(l.revoked, id)
	c := l.items[id]
	now := time.Now()
	c.RevokedAt = &now
	l.items[id] = c
	return c, nil
}
func (l *ledgerFakeLog) MarkReinstate(id, _ string) (issuance.IssuedCredential, error) {
	if l.markErr != nil {
		return issuance.IssuedCredential{}, l.markErr
	}
	l.reinstated = append(l.reinstated, id)
	c := l.items[id]
	c.RevokedAt = nil
	l.items[id] = c
	return c, nil
}
func (l *ledgerFakeLog) VerifyChain() []error { return nil }

func ledgerMkStore(t *testing.T, kind, id string) statuslist.Backend {
	t.Helper()
	s, err := statuslist.NewStore(kind, id, t.TempDir()+"/"+id+".json", "https://issuer.example/status-list/"+kind+"/"+id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ledgerRowID(credentialID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(credentialID))
}

func ledgerRow(credentialID string, revoked bool) map[string]string {
	row := map[string]string{
		"credentialId":           credentialID,
		"credentialType":         "PersonCredential",
		"issuedAt":               "2026-01-02T03:04:05Z",
		"statusListCredentialId": "https://issuer.example/status/1",
		"statusListIndex":        "7",
		"revoked":                "false",
		"claims":                 `{"credentialSubject":{"id":"did:jwk:holder","fullName":"Grace","age":42,"address":{"city":"x"},"tags":["a"]}}`,
	}
	if revoked {
		row["revoked"] = "true"
		row["revokedAt"] = "2026-02-03T00:00:00Z"
	}
	return row
}

func TestInjiLedgerItems(t *testing.T) {
	ctx := context.Background()
	t.Run("no subjects store → nil, nil", func(t *testing.T) {
		items, err := (&H{}).injiLedgerItems(ctx, "owner", "dpg")
		if items != nil || err != nil {
			t.Fatalf("got %v, %v", items, err)
		}
	})
	t.Run("ListMyCredentials error propagates", func(t *testing.T) {
		h := &H{Subjects: &ledgerSubjects{myCredsErr: errors.New("boom")}}
		if _, err := h.injiLedgerItems(ctx, "owner", "dpg"); err == nil || err.Error() != "boom" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("ListLedger error propagates", func(t *testing.T) {
		h := &H{Subjects: &ledgerSubjects{ledgerErr: errors.New("ledger down")}}
		if _, err := h.injiLedgerItems(ctx, "owner", "dpg"); err == nil || err.Error() != "ledger down" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("maps owned keys → ledger rows → issued credentials", func(t *testing.T) {
		f := &ledgerSubjects{
			myCreds: []map[string]string{{"key": "person"}, {"key": ""}, {"key": "degree"}},
			ledger:  []map[string]string{ledgerRow("urn:cred:1", false), ledgerRow("urn:cred:2", true)},
		}
		h := &H{Subjects: f}
		items, err := h.injiLedgerItems(ctx, "owner-1", "inji-ac")
		if err != nil {
			t.Fatal(err)
		}
		if len(f.ledgerKeys) != 1 || strings.Join(f.ledgerKeys[0], ",") != "person,degree" {
			t.Errorf("ListLedger keys = %v (empty keys must be dropped)", f.ledgerKeys)
		}
		if len(items) != 2 || items[0].ID != ledgerRowID("urn:cred:1") || items[0].IssuerDpg != "inji-ac" || items[0].OwnerKey != "owner-1" {
			t.Fatalf("items = %+v", items)
		}
		if items[0].RevokedAt != nil || items[1].RevokedAt == nil {
			t.Errorf("revoked flags wrong: %+v", items)
		}
	})
}

func TestLedgerRowToIssued(t *testing.T) {
	c := ledgerRowToIssued(ledgerRow("urn:cred:1", false), "inji-ac", "owner")
	if c.SchemaName != "PersonCredential" || c.Std != "w3c_vcdm_2" || c.Format != "ldp_vc" || c.Source != "inji" {
		t.Errorf("shape = %+v", c)
	}
	if c.IssuedAt.Format(time.RFC3339) != "2026-01-02T03:04:05Z" {
		t.Errorf("IssuedAt = %v", c.IssuedAt)
	}
	if c.StatusList == nil || c.StatusList.Type != "bitstring" || c.StatusList.ListID != "https://issuer.example/status/1" || c.StatusList.Index != 7 {
		t.Errorf("StatusList = %+v", c.StatusList)
	}
	if c.SubjectFields["fullName"] != "Grace" || c.SubjectFields["credentialId"] != "urn:cred:1" {
		t.Errorf("SubjectFields = %v", c.SubjectFields)
	}

	t.Run("revoked with revokedAt", func(t *testing.T) {
		c := ledgerRowToIssued(ledgerRow("urn:cred:2", true), "d", "o")
		if c.RevokedAt == nil || c.RevokedAt.Format(time.RFC3339) != "2026-02-03T00:00:00Z" {
			t.Errorf("RevokedAt = %v", c.RevokedAt)
		}
	})
	t.Run("revoked without a parseable revokedAt falls back to issuedAt", func(t *testing.T) {
		row := ledgerRow("urn:cred:3", true)
		row["revokedAt"] = "not-a-time"
		c := ledgerRowToIssued(row, "d", "o")
		if c.RevokedAt == nil || !c.RevokedAt.Equal(c.IssuedAt) {
			t.Errorf("RevokedAt = %v, IssuedAt = %v", c.RevokedAt, c.IssuedAt)
		}
	})
}

func TestLedgerClaims(t *testing.T) {
	t.Run("unwraps credentialSubject and skips id/nested values", func(t *testing.T) {
		got := ledgerClaims(ledgerRow("urn:cred:1", false))
		want := map[string]string{"fullName": "Grace", "age": "42", "credentialId": "urn:cred:1"}
		if len(got) != len(want) {
			t.Fatalf("got %v want %v", got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q want %q", k, got[k], v)
			}
		}
	})
	t.Run("flat claims object with @context/type dropped", func(t *testing.T) {
		got := ledgerClaims(map[string]string{"claims": `{"@context":["x"],"type":"T","name":"Ada","ok":true}`})
		if got["name"] != "Ada" || got["ok"] != "true" || len(got) != 2 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("credentialSubject next to other keys is not unwrapped", func(t *testing.T) {
		got := ledgerClaims(map[string]string{"claims": `{"credentialSubject":{"a":"1"},"issuer":"did:web:issuer.example"}`})
		if got["issuer"] != "did:web:issuer.example" || len(got) != 1 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("invalid or empty claims → only credentialId", func(t *testing.T) {
		if got := ledgerClaims(map[string]string{"claims": "{bad", "credentialId": "c"}); len(got) != 1 || got["credentialId"] != "c" {
			t.Errorf("got %v", got)
		}
		if got := ledgerClaims(map[string]string{}); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
}

func TestRecordInjiIssuance(t *testing.T) {
	schema := vctypes.Schema{ID: "PersonCredential", Name: "Person", Std: "w3c_vcdm_2"}
	sess := &Session{IssuerDpg: "inji-ac", UserEmail: "issuer@example.org"}

	t.Run("no log → no-op", func(t *testing.T) {
		(&H{}).recordInjiIssuance(sess, schema, "holder-1", nil, 3, "token")
	})
	t.Run("token kind records vc+sd-jwt with the DPG's list id", func(t *testing.T) {
		log := newLedgerFakeLog()
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: ledgerMkStore(t, "token", "tok-dpg"), Kind: "token", DPG: "inji-ac"})
		h := &H{IssuanceLog: log, StatusLists: set}
		h.recordInjiIssuance(sess, schema, "holder-1", map[string]string{"fullName": "Grace"}, 3, "token")
		if len(log.appended) != 1 {
			t.Fatalf("appended = %d", len(log.appended))
		}
		rec := log.appended[0]
		if !strings.HasPrefix(rec.ID, "vc-") || rec.SchemaID != "PersonCredential" || rec.SchemaName != "Person" || rec.Format != "vc+sd-jwt" ||
			rec.IssuerDpg != "inji-ac" || rec.OwnerKey != "issuer@example.org" || rec.HolderHint != "holder-1" || rec.Source != "inji" {
			t.Errorf("rec = %+v", rec)
		}
		if rec.StatusList == nil || rec.StatusList.Type != "token" || rec.StatusList.ListID != "tok-dpg" || rec.StatusList.Index != 3 {
			t.Errorf("StatusList = %+v", rec.StatusList)
		}
	})
	t.Run("bitstring kind → ldp_vc; missing list → empty id; append error swallowed", func(t *testing.T) {
		log := newLedgerFakeLog()
		h := &H{IssuanceLog: log}
		h.recordInjiIssuance(sess, schema, "h", nil, 0, "bitstring")
		if rec := log.appended[0]; rec.Format != "ldp_vc" || rec.StatusList.ListID != "" {
			t.Errorf("rec = %+v", rec)
		}
		bad := &ledgerFakeLog{appendErr: errors.New("disk full")}
		(&H{IssuanceLog: bad}).recordInjiIssuance(sess, schema, "h", nil, 0, "bitstring")
		if len(bad.appended) != 0 {
			t.Error("append must not record on error")
		}
	})
}

func TestFindLedgerRow(t *testing.T) {
	ctx := context.Background()
	id := ledgerRowID("urn:cred:1")
	t.Run("bad base64 → not found", func(t *testing.T) {
		if _, cid, ok := (&H{}).findLedgerRow(ctx, "o", "!!!"); ok || cid != "" {
			t.Fatalf("got %q %v", cid, ok)
		}
	})
	t.Run("no subjects store", func(t *testing.T) {
		if _, cid, ok := (&H{}).findLedgerRow(ctx, "o", id); ok || cid != "urn:cred:1" {
			t.Fatalf("got %q %v", cid, ok)
		}
	})
	t.Run("store errors → not found", func(t *testing.T) {
		if _, _, ok := (&H{Subjects: &ledgerSubjects{myCredsErr: errors.New("x")}}).findLedgerRow(ctx, "o", id); ok {
			t.Fatal("expected !ok")
		}
		if _, _, ok := (&H{Subjects: &ledgerSubjects{ledgerErr: errors.New("x")}}).findLedgerRow(ctx, "o", id); ok {
			t.Fatal("expected !ok")
		}
	})
	t.Run("matches the decoded credentialId among owned rows", func(t *testing.T) {
		f := &ledgerSubjects{myCreds: []map[string]string{{"key": "k1"}, {"name": "no key"}}, ledger: []map[string]string{ledgerRow("urn:cred:other", false), ledgerRow("urn:cred:1", false)}}
		row, cid, ok := (&H{Subjects: f}).findLedgerRow(ctx, "o", id)
		if !ok || cid != "urn:cred:1" || row["credentialId"] != "urn:cred:1" {
			t.Fatalf("got %v %q %v", row, cid, ok)
		}
		if strings.Join(f.ledgerKeys[0], ",") != "k1" {
			t.Errorf("keys = %v", f.ledgerKeys)
		}
		if _, _, ok := (&H{Subjects: f}).findLedgerRow(ctx, "o", ledgerRowID("urn:cred:missing")); ok {
			t.Error("unknown credential must not be found")
		}
	})
}

// ledgerCertify stands in for Inji Certify's status API.
func ledgerCertify(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/certify/credentials/status" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
	return srv, &bodies
}

func TestSetInjiCredentialStatus(t *testing.T) {
	ctx := context.Background()
	t.Run("posts the status payload", func(t *testing.T) {
		_, bodies := ledgerCertify(t, 200, `{"response":{}}`)
		if err := setInjiCredentialStatus(ctx, "urn:cred:1", "https://issuer.example/status/1", 7, true); err != nil {
			t.Fatal(err)
		}
		b := (*bodies)[0]
		for _, want := range []string{`"credentialId":"urn:cred:1"`, `"status":true`, `"statusListIndex":7`, `"statusListCredential":"https://issuer.example/status/1"`, `"type":"BitstringStatusListEntry"`, `"statusPurpose":"revocation"`} {
			if !strings.Contains(b, want) {
				t.Errorf("body missing %s: %s", want, b)
			}
		}
	})
	t.Run("HTTP >= 400 → error with truncated body", func(t *testing.T) {
		ledgerCertify(t, 500, strings.Repeat("x", 300))
		err := setInjiCredentialStatus(ctx, "c", "l", 0, false)
		if err == nil || !strings.HasPrefix(err.Error(), "certify status 500: ") || !strings.Contains(err.Error(), "…(100 more)") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("2xx with errors envelope → error", func(t *testing.T) {
		ledgerCertify(t, 200, `{"errors":[{"errorCode":"x","errorMessage":"credential not found"}]}`)
		err := setInjiCredentialStatus(ctx, "c", "l", 0, false)
		if err == nil || err.Error() != "certify: credential not found" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("transport error", func(t *testing.T) {
		srv, _ := ledgerCertify(t, 200, "")
		srv.Close()
		if err := setInjiCredentialStatus(ctx, "c", "l", 0, true); err == nil {
			t.Fatal("expected a transport error")
		}
	})
}

func ledgerNewH(t *testing.T, subj SubjectProvisioner, log issuance.Backend) *H {
	t.Helper()
	return &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "issuer_issued_log"), Subjects: subj, IssuanceLog: log}
}

func ledgerPost(path, id string, form url.Values, cookies ...*http.Cookie) *http.Request {
	req := formPost(path, form, cookies...)
	if id != "" {
		req.SetPathValue("id", id)
	}
	return req
}

func TestRevokeReinstateInjiCredential_Ledger(t *testing.T) {
	rowID := ledgerRowID("urn:cred:1")

	t.Run("unknown id → 404 (id from form when no path value)", func(t *testing.T) {
		h := ledgerNewH(t, &ledgerSubjects{}, nil)
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/issuer/credentials/inji/revoke", "", url.Values{"id": {rowID}}))
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "credential not found") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("Certify rejects → toast", func(t *testing.T) {
		ledgerCertify(t, 400, "bad request")
		f := &ledgerSubjects{myCreds: []map[string]string{{"key": "k"}}, ledger: []map[string]string{ledgerRow("urn:cred:1", false)}}
		h := ledgerNewH(t, f, nil)
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/issuer/credentials/inji/x/revoke", rowID, nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("HX-Trigger"), "Status update: certify status 400: bad request") {
			t.Fatalf("got %d HX-Trigger=%q", rr.Code, rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("revoke then reinstate re-render the refreshed row", func(t *testing.T) {
		_, bodies := ledgerCertify(t, 200, `{}`)
		f := &ledgerSubjects{myCreds: []map[string]string{{"key": "k"}}, ledger: []map[string]string{ledgerRow("urn:cred:1", false)}}
		h := ledgerNewH(t, f, nil)
		cookies := seedSession(t, h, func(s *Session) { s.IssuerDpg = "inji-ac" })

		// Simulate Certify flipping the row between the status call and the re-read.
		f.ledger = []map[string]string{ledgerRow("urn:cred:1", true)}
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/issuer/credentials/inji/x/revoke", rowID, nil, cookies...))
		body := rr.Body.String()
		if rr.Code != http.StatusOK || !strings.Contains(body, `id="row-`+rowID+`"`) || !strings.Contains(body, "revoked") || !strings.Contains(body, "Inji auth-code") {
			t.Fatalf("revoke: got %d %q", rr.Code, body)
		}
		if !strings.Contains((*bodies)[0], `"status":true`) {
			t.Errorf("revoke body = %s", (*bodies)[0])
		}

		f.ledger = []map[string]string{ledgerRow("urn:cred:1", false)}
		rr = httptest.NewRecorder()
		h.ReinstateInjiCredential(rr, ledgerPost("/issuer/credentials/inji/x/reinstate", rowID, nil, cookies...))
		if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), `class="schema-card revoked"`) {
			t.Fatalf("reinstate: got %d %q", rr.Code, rr.Body.String())
		}
		if !strings.Contains((*bodies)[1], `"status":false`) {
			t.Errorf("reinstate body = %s", (*bodies)[1])
		}
	})
	t.Run("re-fetch failure keeps the pre-update row", func(t *testing.T) {
		ledgerCertify(t, 200, `{}`)
		f := &ledgerSubjects{myCreds: []map[string]string{{"key": "k"}}, ledger: []map[string]string{ledgerRow("urn:cred:1", false)}}
		h := ledgerNewH(t, f, nil)
		// After the status call the ledger read fails: the handler must still render.
		calls := 0
		wrapped := &ledgerSubjectsFlaky{ledgerSubjects: f, failAfter: 1, calls: &calls}
		h.Subjects = wrapped
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/issuer/credentials/inji/x/revoke", rowID, nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "PersonCredential") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
}

// ledgerSubjectsFlaky fails ListLedger after failAfter successful calls.
type ledgerSubjectsFlaky struct {
	*ledgerSubjects
	failAfter int
	calls     *int
}

func (f *ledgerSubjectsFlaky) ListLedger(ctx context.Context, keys []string) ([]map[string]string, error) {
	*f.calls++
	if *f.calls > f.failAfter {
		return nil, fmt.Errorf("ledger read %d failed", *f.calls)
	}
	return f.ledgerSubjects.ListLedger(ctx, keys)
}

func TestSetInjiStatusRevocation(t *testing.T) {
	owner := func(h *H) []*http.Cookie {
		return seedSession(t, h, func(s *Session) { s.UserEmail = "issuer@example.org" })
	}
	rec := func(binding *issuance.StatusListEntry) issuance.IssuedCredential {
		return issuance.IssuedCredential{ID: "vc-1", OwnerKey: "issuer@example.org", SchemaName: "Person", Std: "w3c_vcdm_2", Format: "ldp_vc", Source: "inji", StatusList: binding}
	}

	t.Run("other owner's record → 404", func(t *testing.T) {
		log := newLedgerFakeLog()
		log.items["vc-1"] = rec(nil)
		h := ledgerNewH(t, nil, log)
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/x", "vc-1", nil, seedSession(t, h, func(s *Session) { s.UserEmail = "someone-else@example.org" })...))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("no status binding → toast", func(t *testing.T) {
		log := newLedgerFakeLog()
		log.items["vc-1"] = rec(&issuance.StatusListEntry{})
		h := ledgerNewH(t, nil, log)
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/x", "vc-1", nil, owner(h)...))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "no status binding") {
			t.Fatalf("HX-Trigger = %q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("store not configured → toast", func(t *testing.T) {
		log := newLedgerFakeLog()
		log.items["vc-1"] = rec(&issuance.StatusListEntry{Type: "token", ListID: "missing"})
		h := ledgerNewH(t, nil, log)
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/x", "vc-1", nil, owner(h)...))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "Status list token not configured.") {
			t.Fatalf("HX-Trigger = %q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("store Revoke / Reinstate errors → toast", func(t *testing.T) {
		log := newLedgerFakeLog()
		log.items["vc-1"] = rec(&issuance.StatusListEntry{Type: "bitstring", ListID: "v1", Index: 1 << 30})
		h := ledgerNewH(t, nil, log)
		h.BitstringStore = ledgerMkStore(t, "bitstring", "v1")
		c := owner(h)
		for _, path := range []string{"revoke", "reinstate"} {
			rr := httptest.NewRecorder()
			req := ledgerPost("/x", "vc-1", nil, c...)
			if path == "revoke" {
				h.RevokeInjiCredential(rr, req)
			} else {
				h.ReinstateInjiCredential(rr, req)
			}
			if !strings.Contains(rr.Header().Get("HX-Trigger"), "Status update: statuslist: index 1073741824 out of range") {
				t.Fatalf("%s: HX-Trigger = %q", path, rr.Header().Get("HX-Trigger"))
			}
		}
	})
	t.Run("log mark error → toast", func(t *testing.T) {
		log := newLedgerFakeLog()
		log.markErr = errors.New("save failed")
		log.items["vc-1"] = rec(&issuance.StatusListEntry{Type: "token", ListID: "v1", Index: 2})
		h := ledgerNewH(t, nil, log)
		h.TokenStore = ledgerMkStore(t, "token", "v1")
		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/x", "vc-1", nil, owner(h)...))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "Mark status: save failed") {
			t.Fatalf("HX-Trigger = %q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("revoke and reinstate flip the bit and re-render", func(t *testing.T) {
		log := newLedgerFakeLog()
		log.items["vc-1"] = rec(&issuance.StatusListEntry{Type: "token", ListID: "tok-1", Index: 5})
		store := ledgerMkStore(t, "token", "tok-1")
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: store, Kind: "token", DPG: "inji-ac"})
		h := ledgerNewH(t, nil, log)
		h.StatusLists = set
		c := owner(h)

		rr := httptest.NewRecorder()
		h.RevokeInjiCredential(rr, ledgerPost("/x", "vc-1", nil, c...))
		if rr.Code != http.StatusOK || !store.IsRevoked(5) || len(log.revoked) != 1 || !strings.Contains(rr.Body.String(), "Revoked:") {
			t.Fatalf("revoke: %d revoked=%v log=%v body=%q", rr.Code, store.IsRevoked(5), log.revoked, rr.Body.String())
		}
		rr = httptest.NewRecorder()
		h.ReinstateInjiCredential(rr, ledgerPost("/x", "vc-1", nil, c...))
		if rr.Code != http.StatusOK || store.IsRevoked(5) || len(log.reinstated) != 1 || strings.Contains(rr.Body.String(), "Revoked:") {
			t.Fatalf("reinstate: %d revoked=%v log=%v", rr.Code, store.IsRevoked(5), log.reinstated)
		}
	})
}
