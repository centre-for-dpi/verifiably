package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/vctypes"
)

// issuedLog opens a real file-backed issuance log under t.TempDir().
func issuedLog(t *testing.T) *issuance.Log {
	t.Helper()
	l, err := issuance.NewLog(t.TempDir() + "/issued.json")
	if err != nil {
		t.Fatalf("issuance.NewLog: %v", err)
	}
	return l
}

func TestRecordIssuance(t *testing.T) {
	schema := vctypes.Schema{ID: "person-sdjwt", Name: "Person", Std: "sd_jwt_vc (IETF)",
		Variants: []vctypes.SchemaVariant{{ID: "person-ldp", Format: "ldp_vc"}, {ID: "person-sdjwt", Format: "vc+sd-jwt"}}}
	sess := &Session{ID: "s1", AuthProvider: "oidc", UserSubject: "sub-1"}

	t.Run("nil log is a no-op", func(t *testing.T) {
		h := &H{}
		h.recordIssuance(sess, schema, "Example DPG", map[string]string{"name": "Ada"}, "openid-credential-offer://x", nil)
	})

	t.Run("appends with holder hint, variant format, owner and binding", func(t *testing.T) {
		log := issuedLog(t)
		h := &H{IssuanceLog: log}
		binding := &backend.StatusListBinding{Type: "token", ListID: "v1", Index: 7}
		h.recordIssuance(sess, schema, "Example DPG", map[string]string{"id": "", "given_name": " Ada "}, "offer-uri", binding)
		items := log.List(issuance.Filter{})
		if len(items) != 1 {
			t.Fatalf("appended %d records, want 1", len(items))
		}
		rec := items[0]
		if !strings.HasPrefix(rec.ID, "vc-") || rec.HolderHint != "Ada" || rec.Format != "vc+sd-jwt" ||
			rec.OwnerKey != "oidc|sub-1" || rec.IssuerDpg != "Example DPG" || rec.OfferURI != "offer-uri" || rec.SchemaName != "Person" {
			t.Fatalf("record = %+v", rec)
		}
		if rec.StatusList == nil || rec.StatusList.Type != "token" || rec.StatusList.ListID != "v1" || rec.StatusList.Index != 7 {
			t.Fatalf("binding = %+v", rec.StatusList)
		}
	})

	t.Run("no hint and no variant match falls back to Std; append error is swallowed", func(t *testing.T) {
		fl := newLedgerFakeLog()
		fl.appendErr = errors.New("disk full")
		h := &H{IssuanceLog: fl}
		s := vctypes.Schema{ID: "x", Name: "X", Std: "w3c_vcdm_2"}
		h.recordIssuance(sess, s, "dpg", map[string]string{"other": "v"}, "", nil)
		if len(fl.appended) != 0 {
			t.Fatalf("append should have failed, got %+v", fl.appended)
		}
		fl.appendErr = nil
		h.recordIssuance(sess, s, "dpg", map[string]string{"other": "v"}, "", nil)
		if len(fl.appended) != 1 || fl.appended[0].Format != "w3c_vcdm_2" || fl.appended[0].HolderHint != "" || fl.appended[0].StatusList != nil {
			t.Fatalf("appended = %+v", fl.appended)
		}
	})
}

func TestSessionOwnerKey(t *testing.T) {
	cases := []struct {
		name string
		sess Session
		want string
	}{
		{"provider+subject", Session{ID: "s", AuthProvider: "p", UserSubject: "u", UserEmail: "e@example.org"}, "p|u"},
		{"email", Session{ID: "s", AuthProvider: "p", UserEmail: "e@example.org"}, "e@example.org"},
		{"session fallback", Session{ID: "abc"}, "session-abc"},
	}
	for _, tc := range cases {
		if got := sessionOwnerKey(&tc.sess); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// issuedSeed appends three records for owner "issuer@example.org" (two on
// "Example DPG", one revoked) plus one foreign-owner record.
func issuedSeed(t *testing.T, log issuance.Backend) {
	t.Helper()
	recs := []issuance.IssuedCredential{
		{ID: "vc-a", SchemaName: "Person", Std: "w3c_vcdm_2", Format: "ldp_vc", IssuerDpg: "Example DPG", OwnerKey: "issuer@example.org", HolderHint: "Ada", SubjectFields: map[string]string{"name": "Ada"}},
		{ID: "vc-b", SchemaName: "Diploma", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt", IssuerDpg: "Example DPG", OwnerKey: "issuer@example.org", HolderHint: "Bob",
			StatusList: &issuance.StatusListEntry{Type: "token", ListID: "v1", Index: 3}},
		{ID: "vc-c", SchemaName: "Badge", Std: "w3c_vcdm_2", Format: "ldp_vc", IssuerDpg: "Other DPG", OwnerKey: "issuer@example.org"},
		{ID: "vc-d", SchemaName: "Foreign", Std: "w3c_vcdm_2", Format: "ldp_vc", IssuerDpg: "Example DPG", OwnerKey: "someone-else",
			StatusList: &issuance.StatusListEntry{Type: "bitstring", ListID: "v1", Index: 1}},
	}
	for _, r := range recs {
		if _, err := log.Append(r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}
	if _, err := log.MarkRevoked("vc-b", "issuer@example.org"); err != nil {
		t.Fatalf("mark revoked: %v", err)
	}
}

func issuedH(t *testing.T, ad backend.Adapter, log issuance.Backend) (*H, []*http.Cookie) {
	t.Helper()
	h := ledgerNewH(t, nil, log)
	h.Adapter = ad
	cookies := seedSession(t, h, func(s *Session) { s.UserEmail = "issuer@example.org"; s.IssuerDpg = "Example DPG" })
	return h, cookies
}

func TestShowIssuedCredentials(t *testing.T) {
	t.Run("no log → 404", func(t *testing.T) {
		h := &H{Sessions: NewStore()}
		rr := httptest.NewRecorder()
		h.ShowIssuedCredentials(rr, httptest.NewRequest(http.MethodGet, "/issuer/credentials", nil))
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "issuance log not configured") {
			t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
		}
	})
	t.Run("renders owner+DPG scoped list with stats", func(t *testing.T) {
		log := issuedLog(t)
		issuedSeed(t, log)
		h, cookies := issuedH(t, &catalogAdapter{issuer: map[string]vctypes.DPG{"Example DPG": {}}}, log)
		req := htmxMainRequest(http.MethodGet, "/issuer/credentials")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.ShowIssuedCredentials(rr, req)
		body := rr.Body.String()
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		for _, want := range []string{"<strong>2</strong> total", "<strong>1</strong> active", "<strong>1</strong> revoked", `id="row-vc-a"`, `id="row-vc-b"`, "token list <code>v1</code> idx 3"} {
			if !strings.Contains(body, want) {
				t.Errorf("body lacks %q", want)
			}
		}
		for _, absent := range []string{"row-vc-c", "row-vc-d", "<!DOCTYPE"} {
			if strings.Contains(body, absent) {
				t.Errorf("body must not contain %q", absent)
			}
		}
	})
}

func TestIssuedCredentialsSearch(t *testing.T) {
	t.Run("no log → 404", func(t *testing.T) {
		h := &H{Sessions: NewStore()}
		rr := httptest.NewRecorder()
		h.IssuedCredentialsSearch(rr, httptest.NewRequest(http.MethodGet, "/issuer/credentials/search", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	log := issuedLog(t)
	issuedSeed(t, log)
	ad := &catalogAdapter{issuer: map[string]vctypes.DPG{"Example DPG": {}}}

	t.Run("form values set filters; 'all' clears", func(t *testing.T) {
		h, cookies := issuedH(t, ad, log)
		req := formPost("/issuer/credentials/search", url.Values{"q": {"bob"}, "std": {"sd_jwt_vc (IETF)"}, "format": {"vc+sd-jwt"}, "state": {"revoked"}}, cookies...)
		rr := httptest.NewRecorder()
		h.IssuedCredentialsSearch(rr, req)
		body := rr.Body.String()
		if !strings.Contains(body, `id="row-vc-b"`) || strings.Contains(body, `id="row-vc-a"`) {
			t.Fatalf("filtered body = %s", body)
		}
		sess := h.Sessions.MustGet(httptest.NewRecorder(), req)
		if sess.IssuedQuery != "bob" || sess.IssuedStd != "sd_jwt_vc (IETF)" || sess.IssuedFormat != "vc+sd-jwt" || sess.IssuedState != "revoked" {
			t.Fatalf("session filter = %q %q %q %q", sess.IssuedQuery, sess.IssuedStd, sess.IssuedFormat, sess.IssuedState)
		}
		req = formPost("/issuer/credentials/search", url.Values{"std": {"all"}, "format": {"all"}, "state": {"all"}}, cookies...)
		rr = httptest.NewRecorder()
		h.IssuedCredentialsSearch(rr, req)
		sess = h.Sessions.MustGet(httptest.NewRecorder(), req)
		if sess.IssuedQuery != "" || sess.IssuedStd != "" || sess.IssuedFormat != "" || sess.IssuedState != "" {
			t.Fatalf("filters not cleared: %q %q %q %q", sess.IssuedQuery, sess.IssuedStd, sess.IssuedFormat, sess.IssuedState)
		}
		if !strings.Contains(rr.Body.String(), `id="row-vc-a"`) || !strings.Contains(rr.Body.String(), `id="row-vc-b"`) {
			t.Fatalf("unfiltered body = %s", rr.Body.String())
		}
	})

	t.Run("query-string filters (empty values via Has)", func(t *testing.T) {
		h, cookies := issuedH(t, ad, log)
		req := httptest.NewRequest(http.MethodGet, "/issuer/credentials/search?q=nobody&std=&format=&state=", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.IssuedCredentialsSearch(rr, req)
		if !strings.Contains(rr.Body.String(), "No credentials match this filter.") {
			t.Fatalf("body = %s", rr.Body.String())
		}
		req = httptest.NewRequest(http.MethodGet, "/issuer/credentials/search?std=w3c_vcdm_2&format=ldp_vc&state=active", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr = httptest.NewRecorder()
		h.IssuedCredentialsSearch(rr, req)
		if !strings.Contains(rr.Body.String(), `id="row-vc-a"`) || strings.Contains(rr.Body.String(), `id="row-vc-b"`) {
			t.Fatalf("body = %s", rr.Body.String())
		}
	})
}

func TestRevokeIssuedCredential_Branches(t *testing.T) {
	newH := func(t *testing.T, log issuance.Backend) (*H, []*http.Cookie) {
		h, cookies := issuedH(t, &catalogAdapter{issuer: map[string]vctypes.DPG{}}, log)
		h.StatusLists = NewStatusListSet()
		return h, cookies
	}
	post := func(h *H, id, formID string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		req := ledgerPost("/issuer/credentials/"+id+"/revoke", id, url.Values{"id": {formID}}, cookies...)
		rr := httptest.NewRecorder()
		h.RevokeIssuedCredential(rr, req)
		return rr
	}

	t.Run("no log → 404", func(t *testing.T) {
		h := &H{Sessions: NewStore()}
		rr := httptest.NewRecorder()
		h.RevokeIssuedCredential(rr, httptest.NewRequest(http.MethodPost, "/issuer/credentials/x/revoke", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("missing id → 400", func(t *testing.T) {
		h, cookies := newH(t, issuedLog(t))
		if rr := post(h, "", "", cookies); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "id required") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("unknown or foreign id → 404 (id from form)", func(t *testing.T) {
		log := issuedLog(t)
		issuedSeed(t, log)
		h, cookies := newH(t, log)
		if rr := post(h, "", "vc-d", cookies); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "credential not found") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if rr := post(h, "", "nope", cookies); rr.Code != http.StatusNotFound {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("no binding → toast", func(t *testing.T) {
		log := issuedLog(t)
		issuedSeed(t, log)
		h, cookies := newH(t, log)
		rr := post(h, "vc-a", "", cookies)
		if rr.Code != 200 || !strings.Contains(rr.Header().Get("HX-Trigger"), "no status list binding") {
			t.Fatalf("status=%d trigger=%q", rr.Code, rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("store not configured → toast", func(t *testing.T) {
		log := issuedLog(t)
		issuedSeed(t, log)
		h, cookies := newH(t, log)
		h.IssuanceLog = log
		// vc-b is already revoked in the seed; use a fresh unrevoked token record.
		log.Append(issuance.IssuedCredential{ID: "vc-t", OwnerKey: "issuer@example.org", IssuerDpg: "Example DPG", StatusList: &issuance.StatusListEntry{Type: "token", ListID: "missing", Index: 2}})
		rr := post(h, "vc-t", "", cookies)
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "Status list token not configured.") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("store revoke error / mark error / success", func(t *testing.T) {
		log := issuedLog(t)
		h, cookies := newH(t, log)
		store := &slFakeStore{id: "v1", revokeErr: errors.New("boom")}
		h.StatusLists.Register(&StatusListEntry{Store: store, Kind: "bitstring"})
		log.Append(issuance.IssuedCredential{ID: "vc-s", SchemaName: "Person", OwnerKey: "issuer@example.org", IssuerDpg: "Example DPG", StatusList: &issuance.StatusListEntry{Type: "bitstring", ListID: "v1", Index: 5}})
		rr := post(h, "vc-s", "", cookies)
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "Revoke: boom") || len(store.revoked) != 1 || store.revoked[0] != 5 {
			t.Fatalf("trigger=%q revoked=%v", rr.Header().Get("HX-Trigger"), store.revoked)
		}
		store.revokeErr = nil
		fl := newLedgerFakeLog()
		fl.items["vc-s"] = issuance.IssuedCredential{ID: "vc-s", OwnerKey: "issuer@example.org", StatusList: &issuance.StatusListEntry{Type: "bitstring", ListID: "v1", Index: 5}}
		fl.markErr = errors.New("chain broken")
		h.IssuanceLog = fl
		rr = post(h, "vc-s", "", cookies)
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "Mark revoked: chain broken") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
		h.IssuanceLog = log
		rr = post(h, "vc-s", "", cookies)
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, `id="row-vc-s"`) || !strings.Contains(body, ">revoked</span>") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		if rec, _ := log.Get("vc-s"); rec.RevokedAt == nil {
			t.Fatal("record not marked revoked")
		}
	})
	t.Run("binding without list id falls back to default store for the kind", func(t *testing.T) {
		log := issuedLog(t)
		h, cookies := newH(t, log)
		store := &slFakeStore{id: "v1"}
		h.StatusLists.Register(&StatusListEntry{Store: store, Kind: "bitstring"})
		log.Append(issuance.IssuedCredential{ID: "vc-old", OwnerKey: "issuer@example.org", StatusList: &issuance.StatusListEntry{Type: "bitstring", Index: 9}})
		rr := post(h, "vc-old", "", cookies)
		if rr.Code != 200 || len(store.revoked) != 1 || store.revoked[0] != 9 {
			t.Fatalf("status=%d revoked=%v", rr.Code, store.revoked)
		}
	})
}

func TestStoreForBinding(t *testing.T) {
	h := &H{StatusLists: NewStatusListSet()}
	if h.storeForBinding("", "v1") != nil {
		t.Fatal("empty kind must return nil")
	}
	if h.storeForBinding("token", "v1") != nil {
		t.Fatal("unregistered kind must return nil")
	}
	tok := &slFakeStore{id: "t1"}
	h.TokenStore = tok
	if got := h.storeForBinding("token", ""); got != tok {
		t.Fatalf("TokenStore fallback: got %v", got)
	}
}

func TestIssuedCredentialsBody_InjiAuthcode(t *testing.T) {
	ledger := &ledgerSubjects{
		myCreds: []map[string]string{{"key": "person"}, {"key": ""}},
		ledger: []map[string]string{
			{"credentialId": "urn:cred:1", "credentialType": "Person", "issuedAt": "2026-01-02T03:04:05Z", "claims": `{"name":"Ada"}`},
			{"credentialId": "urn:cred:2", "credentialType": "Diploma", "issuedAt": "2026-01-03T03:04:05Z", "claims": `{"name":"Bob"}`, "revoked": "true", "revokedAt": "2026-02-01T00:00:00Z"},
		},
	}
	fl := newLedgerFakeLog()
	ad := &catalogAdapter{issuer: map[string]vctypes.DPG{"Inji DPG": {SchemaApply: "inji_authcode"}}}
	h := &H{Adapter: ad, Sessions: NewStore(), Subjects: ledger, IssuanceLog: fl}
	sess := &Session{ID: "s1", UserEmail: "issuer@example.org", IssuerDpg: "Inji DPG"}
	req := httptest.NewRequest(http.MethodGet, "/issuer/credentials", nil)

	data := h.issuedCredentialsBody(sess, req)
	if data.Stats.Total != 2 || data.Stats.Active != 1 || data.Stats.Revoked != 1 || len(data.Items) != 2 {
		t.Fatalf("stats=%+v items=%d", data.Stats, len(data.Items))
	}
	if len(data.Stds) != 3 || data.Stds[0] != "all" || len(data.Formats) != 3 {
		t.Fatalf("chips = %v / %v", data.Stds, data.Formats)
	}

	// Filters: state, std, format, query (schema name + subject field), non-match.
	sess.IssuedState = "active"
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 1 || d.Items[0].SchemaName != "Person" {
		t.Fatalf("active filter items=%+v", d.Items)
	}
	sess.IssuedState = "revoked"
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 1 || d.Items[0].SchemaName != "Diploma" {
		t.Fatalf("revoked filter items=%+v", d.Items)
	}
	sess.IssuedState = ""
	sess.IssuedStd = "mso_mdoc"
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 0 {
		t.Fatalf("std filter items=%+v", d.Items)
	}
	sess.IssuedStd = ""
	sess.IssuedFormat = "mdoc"
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 0 {
		t.Fatalf("format filter items=%+v", d.Items)
	}
	sess.IssuedFormat = ""
	sess.IssuedQuery = "ada"
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 1 || d.Items[0].SchemaName != "Person" {
		t.Fatalf("query(subject) items=%+v", d.Items)
	}
	sess.IssuedQuery = "DIPLOMA"
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 1 || d.Items[0].SchemaName != "Diploma" {
		t.Fatalf("query(schema) items=%+v", d.Items)
	}
	sess.IssuedQuery = "zzz"
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 0 {
		t.Fatalf("query(none) items=%+v", d.Items)
	}

	// Ledger failure → items drop to the IssuanceLog merge only; merge keeps
	// this owner+DPG's token/bitstring entries and skips the rest.
	sess.IssuedQuery = ""
	ledger.myCredsErr = errors.New("db down")
	fl.listItems = []issuance.IssuedCredential{
		{ID: "vc-1", Std: "w3c_vcdm_2", Format: "ldp_vc", OwnerKey: "issuer@example.org", IssuerDpg: "Inji DPG", StatusList: &issuance.StatusListEntry{Type: "token"}},
		{ID: "vc-2", Std: "w3c_vcdm_2", Format: "ldp_vc", OwnerKey: "issuer@example.org", IssuerDpg: "Inji DPG", StatusList: &issuance.StatusListEntry{Type: "bitstring"}},
		{ID: "vc-3", OwnerKey: "issuer@example.org", IssuerDpg: "Inji DPG"},
		{ID: "vc-4", OwnerKey: "issuer@example.org", IssuerDpg: "Other", StatusList: &issuance.StatusListEntry{Type: "token"}},
	}
	d := h.issuedCredentialsBody(sess, req)
	if len(d.Items) != 2 || d.Items[0].ID != "vc-1" || d.Items[1].ID != "vc-2" {
		t.Fatalf("merged items=%+v", d.Items)
	}
	h.IssuanceLog = nil
	if d := h.issuedCredentialsBody(sess, req); len(d.Items) != 0 {
		t.Fatalf("nil log items=%+v", d.Items)
	}

	// ListIssuerDpgs error → not auth-code → the walt.id path (nil request also).
	h.IssuanceLog = fl
	ad.issuerErr = errors.New("catalog down")
	// The walt.id path keeps every owner+DPG record (vc-1..vc-3, binding or
	// not) and derives the chips from them instead of the fixed Inji rows.
	d = h.issuedCredentialsBody(sess, req)
	if len(d.Items) != 3 || d.Stats.Total != 3 || d.Stats.ByStd["w3c_vcdm_2"] != 2 || len(d.Stds) != 3 || d.Stds[0] != "all" {
		t.Fatalf("fallback path chips=%v items=%d stats=%+v", d.Stds, len(d.Items), d.Stats)
	}
	if d := h.issuedCredentialsBody(sess, nil); len(d.Items) != 3 || d.Stats.ByFormat["ldp_vc"] != 2 {
		t.Fatalf("nil request items=%d stats=%+v", len(d.Items), d.Stats)
	}
}

func TestFilterIssuedByDpg(t *testing.T) {
	in := []issuance.IssuedCredential{{ID: "a", IssuerDpg: "x"}, {ID: "b", IssuerDpg: "y"}}
	if got := filterIssuedByDpg(in, ""); len(got) != 2 {
		t.Fatalf("empty dpg: %v", got)
	}
	if got := filterIssuedByDpg(in, "y"); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("dpg y: %v", got)
	}
}
