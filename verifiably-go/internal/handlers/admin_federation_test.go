package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/didresolver"
	"github.com/verifiably/verifiably-go/internal/trust"
)

type fedResolver struct{ err error }

func (r fedResolver) Resolve(context.Context, string) (didresolver.DIDDocument, error) {
	return didresolver.DIDDocument{}, r.err
}

type fedRegistrar struct{ calls [][3]string }

func (f *fedRegistrar) RegisterMemberVerifier(did, ep, key string) {
	f.calls = append(f.calls, [3]string{did, ep, key})
}

func fedMember() trust.TrustedIssuer {
	return trust.TrustedIssuer{DID: "did:web:issuer.example", DisplayName: "Example Issuer", Schemas: []string{"Diploma"},
		ServiceEndpoint: "https://issuer.example", VerifierAPIKey: "old-key", StatusListPolicy: "fail-open",
		AccreditedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func fedH(t *testing.T, reg trust.Registry, admin bool) (*H, []*http.Cookie) {
	t.Helper()
	h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "admin_federation"), TrustRegistry: reg}
	cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = admin })
	return h, cookies
}

// fedReq builds a request with the {did} path value; htmx toggles the HX headers.
func fedReq(method, path, did string, v url.Values, htmx bool, cookies []*http.Cookie) *http.Request {
	var req *http.Request
	if v != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	if did != "" {
		req.SetPathValue("did", did)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// fedHealthz serves /healthz with the given status.
func fedHealthz(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestShowFederationMembers(t *testing.T) {
	t.Run("not admin / no registry / list error", func(t *testing.T) {
		h, cookies := fedH(t, &trustFakeRegistry{}, false)
		rr := httptest.NewRecorder()
		h.ShowFederationMembers(rr, fedReq(http.MethodGet, "/admin/federation/members", "", nil, false, cookies))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/admin/login" {
			t.Fatalf("status=%d", rr.Code)
		}
		h, cookies = fedH(t, nil, true)
		rr = httptest.NewRecorder()
		h.ShowFederationMembers(rr, fedReq(http.MethodGet, "/admin/federation/members", "", nil, false, cookies))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d", rr.Code)
		}
		h, cookies = fedH(t, &trustFakeRegistry{listErr: errors.New("db down")}, true)
		rr = httptest.NewRecorder()
		h.ShowFederationMembers(rr, fedReq(http.MethodGet, "/admin/federation/members", "", nil, true, cookies))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "Could not load members: db down") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("full page and HTMX fragment with keys + health", func(t *testing.T) {
		reg := &trustFakeRegistry{issuers: []trust.TrustedIssuer{fedMember()}}
		h, cookies := fedH(t, reg, true)
		h.IssuerAPIKeyStore = &mockAPIKeyStore{hasKeys: map[string]bool{"did:web:issuer.example": true}}
		h.TrustHealthMonitor = trust.NewMonitor()
		rr := httptest.NewRecorder()
		h.ShowFederationMembers(rr, fedReq(http.MethodGet, "/admin/federation/members", "", nil, false, cookies))
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, "did:web:issuer.example") || !strings.Contains(body, "api-key/revoke") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		rr = httptest.NewRecorder()
		h.ShowFederationMembers(rr, fedReq(http.MethodGet, "/admin/federation/members", "", nil, true, cookies))
		if body := rr.Body.String(); strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, "Example Issuer") {
			t.Fatalf("fragment body=%s", body)
		}
	})
}

func TestMemberKeyAndHealthMaps(t *testing.T) {
	h := &H{}
	members := []trust.TrustedIssuer{{DID: "did:web:a"}, {DID: "did:web:b"}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if m := h.memberKeyMap(req, members); len(m) != 0 {
		t.Fatalf("nil store: %v", m)
	}
	if m := h.memberHealthMap(members); len(m) != 0 {
		t.Fatalf("nil monitor: %v", m)
	}
	h.IssuerAPIKeyStore = &mockAPIKeyStore{hasKeys: map[string]bool{"did:web:a": true}}
	h.TrustHealthMonitor = trust.NewMonitor()
	if m := h.memberKeyMap(req, members); !m["did:web:a"] || m["did:web:b"] {
		t.Fatalf("keys: %v", m)
	}
	if m := h.memberHealthMap(members); len(m) != 2 || m["did:web:a"].Checked {
		t.Fatalf("health: %v", m)
	}
}

func TestRegisterFederationMember(t *testing.T) {
	const path = "/admin/federation/members"
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }

	t.Run("auth and configuration guards", func(t *testing.T) {
		h, cookies := fedH(t, &trustFakeRegistry{}, false)
		rr := httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", url.Values{}, false, cookies))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d", rr.Code)
		}
		h, cookies = fedH(t, nil, true)
		rr = httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", url.Values{}, false, cookies))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("JSON body: invalid, then registered with a redirect", func(t *testing.T) {
		reg := &trustFakeRegistry{}
		h, cookies := fedH(t, reg, true)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{bad"))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.RegisterFederationMember(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid JSON") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"did":"did:web:new.example","display_name":"New"}`))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr = httptest.NewRecorder()
		h.RegisterFederationMember(rr, req)
		if rr.Code != http.StatusSeeOther || len(reg.added) != 1 || reg.added[0].DID != "did:web:new.example" {
			t.Fatalf("status=%d added=%+v", rr.Code, reg.added)
		}
	})
	t.Run("form validation", func(t *testing.T) {
		h, cookies := fedH(t, &trustFakeRegistry{}, true)
		rr := httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", url.Values{"did": {"did:web:x"}, "valid_until": {"not-a-date"}}, true, cookies))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "valid_until must be YYYY-MM-DD") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		rr = httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", url.Values{}, true, cookies))
		if !strings.Contains(trig(rr), "DID is required") {
			t.Fatalf("trigger=%q", trig(rr))
		}
		rr = httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", url.Values{"did": {"did:key:z6Mk"}}, true, cookies))
		if !strings.Contains(trig(rr), "must be a did:web: identifier") {
			t.Fatalf("trigger=%q", trig(rr))
		}
	})
	t.Run("healthz failure, registry error, then success wires the verifier", func(t *testing.T) {
		reg := &trustFakeRegistry{addErr: errors.New("duplicate")}
		h, cookies := fedH(t, reg, true)
		h.DIDResolver = fedResolver{err: errors.New("unresolvable")}
		wired := &fedRegistrar{}
		h.MemberVerifierRegistrar = wired
		h.IssuerAPIKeyStore = &mockAPIKeyStore{}
		down := fedHealthz(t, http.StatusBadGateway)
		rr := httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", url.Values{"did": {"did:web:x"}, "service_endpoint": {down.URL + "/"}}, true, cookies))
		if !strings.Contains(trig(rr), "Healthz check failed") || !strings.Contains(trig(rr), "returned HTTP 502") {
			t.Fatalf("trigger=%q", trig(rr))
		}
		up := fedHealthz(t, http.StatusOK)
		form := url.Values{"did": {" did:web:x "}, "display_name": {"X"}, "service_endpoint": {up.URL + "/"},
			"schemas": {"A, ,B"}, "status_list_endpoints": {up.URL + "/status/1, "}, "verifier_api_key": {"k1"}, "valid_until": {"2031-02-03"}}
		rr = httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", form, true, cookies))
		if !strings.Contains(trig(rr), "Could not register member: duplicate") {
			t.Fatalf("trigger=%q", trig(rr))
		}
		reg.addErr = nil
		rr = httptest.NewRecorder()
		h.RegisterFederationMember(rr, fedReq(http.MethodPost, path, "", form, true, cookies))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "did:web:x") || strings.Contains(rr.Body.String(), "<!DOCTYPE") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		e := reg.added[0]
		if e.DID != "did:web:x" || e.ServiceEndpoint != up.URL || len(e.Schemas) != 2 || len(e.StatusListEndpoints) != 1 || e.StatusListPolicy != "fail-closed" ||
			e.VerifierAPIKey != "k1" || !e.ValidUntil.Equal(time.Date(2031, 2, 3, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("entry=%+v", e)
		}
		if len(wired.calls) != 1 || wired.calls[0] != [3]string{"did:web:x", up.URL, "k1"} {
			t.Fatalf("wired=%v", wired.calls)
		}
	})
}

func TestDeleteFederationMember(t *testing.T) {
	const path = "/admin/federation/members/x/delete"
	h, cookies := fedH(t, &trustFakeRegistry{}, false)
	rr := httptest.NewRecorder()
	h.DeleteFederationMember(rr, fedReq(http.MethodPost, path, "did:web:x", nil, false, cookies))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	h, cookies = fedH(t, nil, true)
	rr = httptest.NewRecorder()
	h.DeleteFederationMember(rr, fedReq(http.MethodPost, path, "did:web:x", nil, false, cookies))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
	reg := &trustFakeRegistry{rmErr: errors.New("locked"), issuers: []trust.TrustedIssuer{fedMember()}}
	h, cookies = fedH(t, reg, true)
	rr = httptest.NewRecorder()
	h.DeleteFederationMember(rr, fedReq(http.MethodPost, path, "", nil, false, cookies))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.DeleteFederationMember(rr, fedReq(http.MethodPost, path, "did:web:x", nil, true, cookies))
	if !strings.Contains(rr.Header().Get("HX-Trigger"), "Could not remove member: locked") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	reg.rmErr = nil
	rr = httptest.NewRecorder()
	h.DeleteFederationMember(rr, fedReq(http.MethodPost, path, "did:web:x", nil, true, cookies))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "did:web:issuer.example") || len(reg.removed) != 1 {
		t.Fatalf("status=%d removed=%v", rr.Code, reg.removed)
	}
	rr = httptest.NewRecorder()
	h.DeleteFederationMember(rr, fedReq(http.MethodPost, path, "did:web:x", nil, false, cookies))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestIssueAndRevokeAPIKey(t *testing.T) {
	const path = "/admin/federation/members/x/api-key"
	for _, fn := range []string{"issue", "revoke"} {
		call := func(h *H, did string, cookies []*http.Cookie) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			req := fedReq(http.MethodPost, path, did, nil, true, cookies)
			if fn == "issue" {
				h.IssueAPIKey(rr, req)
			} else {
				h.RevokeAPIKey(rr, req)
			}
			return rr
		}
		h, cookies := fedH(t, &trustFakeRegistry{}, false)
		if rr := call(h, "did:web:x", cookies); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status=%d", fn, rr.Code)
		}
		h, cookies = fedH(t, &trustFakeRegistry{}, true)
		if rr := call(h, "did:web:x", cookies); rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status=%d", fn, rr.Code)
		}
		store := &mockAPIKeyStore{issueErr: errors.New("hash failed"), revokeErr: errors.New("hash failed")}
		h.IssuerAPIKeyStore = store
		if rr := call(h, "", cookies); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d", fn, rr.Code)
		}
		if rr := call(h, "did:web:x", cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "hash failed") {
			t.Fatalf("%s: trigger=%q", fn, rr.Header().Get("HX-Trigger"))
		}
		store.issueErr, store.revokeErr = nil, nil
		rr := call(h, "did:web:x", cookies)
		if rr.Code != 200 {
			t.Fatalf("%s: status=%d", fn, rr.Code)
		}
		if fn == "issue" && !strings.Contains(rr.Body.String(), "token-for-did:web:x") {
			t.Fatalf("issue body=%s", rr.Body.String())
		}
		if fn == "revoke" && (len(store.revoked) != 1 || !strings.Contains(rr.Body.String(), `<table class="cred-table"`) || strings.Contains(rr.Body.String(), "did:web:")) {
			t.Fatalf("revoke revoked=%v body=%s", store.revoked, rr.Body.String())
		}
	}
}

func TestShowEditFederationMember(t *testing.T) {
	const path = "/admin/federation/members/x/edit"
	h, cookies := fedH(t, &trustFakeRegistry{}, false)
	rr := httptest.NewRecorder()
	h.ShowEditFederationMember(rr, fedReq(http.MethodGet, path, "did:web:x", nil, true, cookies))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	h, cookies = fedH(t, nil, true)
	rr = httptest.NewRecorder()
	h.ShowEditFederationMember(rr, fedReq(http.MethodGet, path, "did:web:x", nil, true, cookies))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
	reg := &trustFakeRegistry{listErr: errors.New("db down")}
	h, cookies = fedH(t, reg, true)
	rr = httptest.NewRecorder()
	h.ShowEditFederationMember(rr, fedReq(http.MethodGet, path, "", nil, true, cookies))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ShowEditFederationMember(rr, fedReq(http.MethodGet, path, "did:web:x", nil, true, cookies))
	if !strings.Contains(rr.Header().Get("HX-Trigger"), "Could not load members: db down") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	reg.listErr = nil
	reg.issuers = []trust.TrustedIssuer{fedMember()}
	rr = httptest.NewRecorder()
	h.ShowEditFederationMember(rr, fedReq(http.MethodGet, path, "did:web:missing", nil, true, cookies))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ShowEditFederationMember(rr, fedReq(http.MethodGet, path, "did:web:issuer.example", nil, true, cookies))
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, `value="Example Issuer"`) || !strings.Contains(body, `value="2030-01-01"`) || !strings.Contains(body, `<option value="fail-open" selected>`) || !strings.Contains(body, "Leave blank to keep existing key") {
		t.Fatalf("status=%d body=%s", rr.Code, body)
	}
}

func TestUpdateFederationMember(t *testing.T) {
	const path = "/admin/federation/members/x/edit"
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }
	post := func(h *H, did string, v url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.UpdateFederationMember(rr, fedReq(http.MethodPost, path, did, v, true, cookies))
		return rr
	}
	h, cookies := fedH(t, &trustFakeRegistry{}, false)
	if rr := post(h, "did:web:x", url.Values{}, cookies); rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	h, cookies = fedH(t, nil, true)
	if rr := post(h, "did:web:x", url.Values{}, cookies); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
	reg := &trustFakeRegistry{listErr: errors.New("db down")}
	h, cookies = fedH(t, reg, true)
	if rr := post(h, "", url.Values{}, cookies); rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
	if rr := post(h, "did:web:x", url.Values{}, cookies); !strings.Contains(trig(rr), "Could not load member: db down") {
		t.Fatalf("trigger=%q", trig(rr))
	}
	reg.listErr = nil
	reg.issuers = []trust.TrustedIssuer{fedMember()}
	if rr := post(h, "did:web:missing", url.Values{}, cookies); !strings.Contains(trig(rr), "Member not found") {
		t.Fatalf("trigger=%q", trig(rr))
	}
	const did = "did:web:issuer.example"
	if rr := post(h, did, url.Values{"valid_until": {"bad"}}, cookies); !strings.Contains(trig(rr), "valid_until must be YYYY-MM-DD") {
		t.Fatalf("trigger=%q", trig(rr))
	}
	if rr := post(h, did, url.Values{"service_endpoint": {"http://127.0.0.1:1"}}, cookies); !strings.Contains(trig(rr), "Healthz check failed") {
		t.Fatalf("trigger=%q", trig(rr))
	}
	reg.addErr = errors.New("write failed")
	if rr := post(h, did, url.Values{"display_name": {"Renamed"}}, cookies); !strings.Contains(trig(rr), "Could not update member: write failed") {
		t.Fatalf("trigger=%q", trig(rr))
	}
	reg.addErr = nil
	// No endpoint + blank key: existing key preserved, defaults applied, registrar not called.
	wired := &fedRegistrar{}
	h.MemberVerifierRegistrar = wired
	rr := post(h, did, url.Values{"display_name": {"Renamed"}, "schemas": {"A,B"}, "status_list_endpoints": {"https://issuer.example/s1"}, "valid_until": {"2032-05-06"}}, cookies)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Renamed") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	e := reg.added[len(reg.added)-1]
	if e.VerifierAPIKey != "old-key" || e.StatusListPolicy != "fail-closed" || len(e.Schemas) != 2 || len(e.StatusListEndpoints) != 1 || !e.AccreditedAt.Equal(fedMember().AccreditedAt) || !e.ValidUntil.Equal(time.Date(2032, 5, 6, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("entry=%+v", e)
	}
	if len(wired.calls) != 0 {
		t.Fatalf("registrar must not be called without an endpoint: %v", wired.calls)
	}
	// Healthy endpoint + new key → re-wired.
	up := fedHealthz(t, http.StatusOK)
	rr = post(h, did, url.Values{"service_endpoint": {up.URL + "/"}, "verifier_api_key": {"new-key"}, "status_list_policy": {"fail-open"}}, cookies)
	if rr.Code != 200 || len(wired.calls) != 1 || wired.calls[0] != [3]string{did, up.URL, "new-key"} {
		t.Fatalf("status=%d wired=%v", rr.Code, wired.calls)
	}
	if e := reg.added[len(reg.added)-1]; e.StatusListPolicy != "fail-open" {
		t.Fatalf("entry=%+v", e)
	}
}

func TestFederationHealthz(t *testing.T) {
	ctx := context.Background()
	if err := federationHealthz(ctx, "http://bad host"); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("err=%v", err)
	}
	if err := federationHealthz(ctx, "http://127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "GET http://127.0.0.1:1/healthz:") {
		t.Fatalf("err=%v", err)
	}
	srv := fedHealthz(t, http.StatusServiceUnavailable)
	if err := federationHealthz(ctx, srv.URL+"/"); err == nil || !strings.Contains(err.Error(), "returned HTTP 503") {
		t.Fatalf("err=%v", err)
	}
	ok := fedHealthz(t, http.StatusOK)
	if err := federationHealthz(ctx, ok.URL); err != nil {
		t.Fatalf("err=%v", err)
	}
}
