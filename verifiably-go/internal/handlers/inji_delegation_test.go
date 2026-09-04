package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// ─── fixtures ─────────────────────────────────────────────────────────────────

// injiDelegSDJWT builds a compact SD-JWT whose payload carries vct + iss and
// one disclosure (subjectRef).
func injiDelegSDJWT(t *testing.T, vct string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"vc+sd-jwt"}`))
	pl, _ := json.Marshal(map[string]any{"vct": vct, "iss": "did:web:issuer.example", "_sd": []string{"x"}})
	return hdr + "." + base64.RawURLEncoding.EncodeToString(pl) + ".AAAA~" + discl("subjectRef", "urn:person:1") + "~"
}

// injiDelegLDCred is a JSON-LD DelegatedAccessCredential object (as stored raw
// in the in-app Inji wallet) so the evaluator produces a verdict.
func injiDelegLDCred() string {
	b, _ := json.Marshal(map[string]any{
		"type":   []string{"VerifiableCredential", "DelegatedAccessCredential"},
		"issuer": "did:web:issuer.example",
		"credentialSubject": map[string]any{
			"id": "did:example:delegate", "onBehalfOf": "urn:person:1", "role": "Guardian", "allowedAction": "present",
		},
	})
	return string(b)
}

// injiDelegDIDServer serves certify's did.json so certifyIssuerDID resolves on
// its first attempt (no retry sleeps), and returns the server for reuse.
func injiDelegDIDServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	if mux == nil {
		mux = http.NewServeMux()
	}
	mux.HandleFunc("/v1/certify/.well-known/did.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"did:web:issuer.example"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
	return srv
}

// injiDelegMockIdentity serves the eSignet mock-identity create endpoint with
// the given JSON body/status.
func injiDelegMockIdentity(t *testing.T, status int, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mock-identity-system/identity" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("MOCK_IDENTITY_URL", srv.URL)
}

func injiDelegTokenStore(t *testing.T) *statuslist.Store {
	t.Helper()
	st, err := statuslist.NewStore("token", "tok1", filepath.Join(t.TempDir(), "tok.json"), "https://issuer.example/status-list/token/tok1")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func injiDelegDo(h *H, fn http.HandlerFunc, req *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	rr := httptest.NewRecorder()
	fn(rr, req)
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	return rr, m
}

// ─── pure helpers ─────────────────────────────────────────────────────────────

func TestInjiAuthcodeAndPreAuthSchema(t *testing.T) {
	s := injiAuthcodeSchema("Person", "", []string{"a", "b"})
	if s.ID != "Person" || s.Std != "sd_jwt_vc (IETF)" || !s.Custom || len(s.FieldsSpec) != 2 || s.FieldsSpec[1].Name != "b" || s.AdditionalTypes[0] != "Person" {
		t.Fatalf("authcode schema = %+v", s)
	}
	if s2 := injiAuthcodeSchema("Person", "w3c_vcdm_2", nil); s2.Std != "w3c_vcdm_2" || len(s2.FieldsSpec) != 0 {
		t.Fatalf("std not kept: %+v", s2)
	}
	p := injiPreAuthSchema("Person", "Inji Certify · Pre-Auth", "", []string{"x"})
	if p.ID != "dapre-person" || p.Std != "sd_jwt_vc (IETF)" || p.DPGs[0] != "Inji Certify · Pre-Auth" || p.FieldsSpec[0].Name != "x" {
		t.Fatalf("preauth schema = %+v", p)
	}
	if c := injiPreAuthSchema("Person", "CREDEBL", "w3c_vcdm_2", nil); c.ID != "custom-da-person" || c.Std != "w3c_vcdm_2" {
		t.Fatalf("credebl schema = %+v", c)
	}
}

func TestNormalizeClaimedInjiCreds(t *testing.T) {
	sd := injiDelegSDJWT(t, "Person")
	quoted, _ := json.Marshal(sd)
	out := normalizeClaimedInjiCreds([]string{
		"", "   ",
		injiDelegLDCred(),   // JSON object
		string(quoted),      // quoted compact SD-JWT
		sd,                  // raw compact SD-JWT
		`"no-tilde-string"`, // quoted string without ~ → ignored
		"bad~sdjwt",         // raw with ~ but undecodable payload → ignored
		`"x~y"`,             // quoted with ~ but undecodable → ignored
		"{}",                // empty object → not an object with keys, no ~ → ignored
	})
	if len(out) != 3 {
		t.Fatalf("got %d creds: %+v", len(out), out)
	}
	if out[0].Types[1] != "DelegatedAccessCredential" || out[1].Types[0] != "Person" || out[2].Claims["subjectRef"] != "urn:person:1" {
		t.Fatalf("normalised = %+v", out)
	}
}

func TestNormalizeWalletCred(t *testing.T) {
	nc := normalizeWalletCred(vctypes.Credential{Type: "Person", Issuer: "did:web:issuer.example", Format: "vc+sd-jwt", Fields: map[string]string{"subjectRef": "urn:person:1"}})
	if nc.Types[0] != "Person" || nc.Issuer != "did:web:issuer.example" || nc.Format != "vc+sd-jwt" || nc.Claims["subjectRef"] != "urn:person:1" || nc.Raw["subjectRef"] != "urn:person:1" {
		t.Fatalf("normalised = %+v", nc)
	}
}

func TestInjiGetJSON(t *testing.T) {
	var out map[string]any
	if err := injiGetJSON(context.Background(), "http://127.0.0.1:1/\n", &out); err == nil {
		t.Error("bad URL must fail to build a request")
	}
	if err := injiGetJSON(context.Background(), "http://127.0.0.1:1/x", &out); err == nil {
		t.Error("unreachable host must error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"a":1}`) }))
	defer srv.Close()
	if err := injiGetJSON(context.Background(), srv.URL, &out); err != nil || out["a"] != float64(1) {
		t.Fatalf("err=%v out=%v", err, out)
	}
}

// ─── APIInjiDelegationSetup ───────────────────────────────────────────────────

func TestAPIInjiDelegationSetup(t *testing.T) {
	path := "/api/v1/delegation/inji/setup"
	t.Run("unauthenticated", func(t *testing.T) {
		rr, m := injiDelegDo(nil, (&H{APIKeys: ParseAPIKeys("test:secret")}).APIInjiDelegationSetup, httptest.NewRequest(http.MethodPost, path, nil))
		if rr.Code != http.StatusUnauthorized || m["error"] == nil {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		req := authPOST(t, path, nil)
		req.Body = io.NopCloser(strings.NewReader("{"))
		rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationSetup, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid JSON") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("missing individualId/pin", func(t *testing.T) {
		rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationSetup, authPOST(t, path, map[string]any{"individualId": "1"}))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "individualId and pin are required") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("mock identity hard error", func(t *testing.T) {
		injiDelegMockIdentity(t, http.StatusOK, `{"errors":[{"errorCode":"E1","errorMessage":"boom"}]}`)
		rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationSetup, authPOST(t, path, map[string]any{"individualId": "1", "pin": "1234"}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "create mock identity: boom") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("mock identity duplicate is tolerated; missing config fails at DB apply (before any restart)", func(t *testing.T) {
		injiDelegMockIdentity(t, http.StatusOK, `{"errors":[{"errorCode":"DUP","errorMessage":"identity already exists"}]}`)
		injiDelegDIDServer(t, nil)
		// SAFETY: applyErr makes applyAuthcodeSchema return at "DB apply failed",
		// long before its dockerRestart loop (inji_schema.go:412-416).
		f := &fakeSubjects{listCredsErr: errors.New("list down"), applyErr: errors.New("db down")}
		h := apiTestH(nil)
		h.Subjects = f
		rr, _ := injiDelegDo(h, h.APIInjiDelegationSetup, authPOST(t, path, map[string]any{"individualId": "1", "pin": "1234"}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "create config BirthCertificate: DB apply failed: db down") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		if len(f.applyDIDs) != 1 || f.applyDIDs[0] != "did:web:issuer.example" {
			t.Fatalf("applyDIDs = %v", f.applyDIDs)
		}
	})
	existing := []map[string]string{{"key": "BirthCertificate"}, {"key": "DelegatedAccessCredential"}, {"key": "Guardianship"}}
	t.Run("w3c: configs exist, no status binding, provision error", func(t *testing.T) {
		injiDelegMockIdentity(t, http.StatusOK, `{"response":{}}`)
		f := &fakeSubjects{listCreds: existing, provErr: errors.New("pg down")}
		h := apiTestH(nil)
		h.Subjects = f
		rr, _ := injiDelegDo(h, h.APIInjiDelegationSetup, authPOST(t, path, map[string]any{"individualId": "1", "pin": "1234", "std": "w3c_vcdm_2"}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "provision vc_subject: pg down") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		if len(f.applyDIDs) != 0 {
			t.Fatal("existing configs must not be re-applied")
		}
	})
	t.Run("w3c success with custom types, validUntil and actions", func(t *testing.T) {
		injiDelegMockIdentity(t, http.StatusOK, `{"response":{}}`)
		f := &fakeSubjects{listCreds: existing}
		h := apiTestH(nil)
		h.Subjects = f
		rr, m := injiDelegDo(h, h.APIInjiDelegationSetup, authPOST(t, path, map[string]any{
			"individualId": "1", "pin": "1234", "std": "w3c_vcdm_2", "delegationType": "Guardianship",
			"validUntil": "2030-01-01", "allowedAction": []string{"present", "sign"}, "role": "Guardian", "subjectRef": "urn:person:1", "givenName": "Alex",
		}))
		if rr.Code != http.StatusCreated {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		if m["delegationCredential"] != "Guardianship" || m["claimURLs"].(map[string]any)["delegation"] != "/holder/wallet/inji/start?cred=Guardianship" || m["statusListIndex"] != nil {
			t.Fatalf("out = %v", m)
		}
		if len(f.provCalls) != 1 {
			t.Fatalf("provCalls = %+v", f.provCalls)
		}
		claims := f.provCalls[0].claims
		if claims[subjectClaimKey("guardianship", "valid_until")] != "2030-01-01" || claims[subjectClaimKey("guardianship", "allowedAction")] != "present,sign" ||
			claims[subjectClaimKey("guardianship", "role")] != "Guardian" || claims[subjectClaimKey("birthcertificate", "givenName")] != "Alex" {
			t.Fatalf("claims = %v", claims)
		}
		if f.provCalls[0].subjectID != esignetSubjectID("1", injiAuthcodeClientID()) {
			t.Fatalf("subjectID = %q", f.provCalls[0].subjectID)
		}
	})
	t.Run("sd-jwt: status list allocate error", func(t *testing.T) {
		injiDelegMockIdentity(t, http.StatusOK, `{"response":{}}`)
		h := apiTestH(nil)
		h.Subjects = &fakeSubjects{listCreds: existing}
		h.TokenStore = &slFakeStore{allocErr: errors.New("full")}
		rr, _ := injiDelegDo(h, h.APIInjiDelegationSetup, authPOST(t, path, map[string]any{"individualId": "1", "pin": "1234"}))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "status list: status list allocate: full") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("sd-jwt success carries the status binding", func(t *testing.T) {
		injiDelegMockIdentity(t, http.StatusOK, `{"response":{}}`)
		f := &fakeSubjects{listCreds: existing}
		h := apiTestH(nil)
		h.Subjects = f
		h.TokenStore = injiDelegTokenStore(t)
		rr, m := injiDelegDo(h, h.APIInjiDelegationSetup, authPOST(t, path, map[string]any{"individualId": "1", "pin": "1234"}))
		if rr.Code != http.StatusCreated {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		if m["statusListIndex"] != float64(0) || m["statusType"] != "token" || m["statusListCredential"] != "https://issuer.example/status-list/token/tok1" {
			t.Fatalf("out = %v", m)
		}
		claims := f.provCalls[0].claims
		if claims[injiStatusIdxKey("delegatedaccesscredential")] != "0" || claims[subjectClaimKey("delegatedaccesscredential", "role")] != "Mother" {
			t.Fatalf("claims = %v", claims)
		}
	})
}

// ─── APIInjiDelegationRevoke ──────────────────────────────────────────────────

func TestAPIInjiDelegationRevoke(t *testing.T) {
	path := "/api/v1/delegation/inji/revoke"
	t.Run("unauthenticated", func(t *testing.T) {
		rr, _ := injiDelegDo(nil, (&H{}).APIInjiDelegationRevoke, httptest.NewRequest(http.MethodPost, path, nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		req := authPOST(t, path, nil)
		req.Body = io.NopCloser(strings.NewReader("["))
		rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationRevoke, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("certify path needs both ids", func(t *testing.T) {
		rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"type": "certify", "index": 3}))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "certify revoke needs") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("certify path upstream error", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"certifyCredentialId": "c1", "statusListId": "l1", "index": 3}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "certify status:") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("certify path revoke and reinstate", func(t *testing.T) {
		var got []map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			got = append(got, m)
			_, _ = io.WriteString(w, `{"response":{}}`)
		}))
		defer srv.Close()
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		rr, m := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"certifyCredentialId": "c1", "statusListId": "l1", "index": 3}))
		if rr.Code != http.StatusOK || m["revoked"] != float64(3) || m["via"] != "certify" {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		rr, m = injiDelegDo(nil, apiTestH(nil).APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"certifyCredentialId": "c1", "statusListId": "l1", "index": 3, "reinstate": true}))
		if rr.Code != http.StatusOK || m["reinstated"] != float64(3) {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		if len(got) != 2 || got[0]["status"] != true || got[1]["status"] != false || got[0]["credentialId"] != "c1" {
			t.Fatalf("certify calls = %v", got)
		}
	})
	t.Run("no store configured", func(t *testing.T) {
		rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"index": 1, "type": "bitstring"}))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "no status store for type bitstring") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("token store revoke/reinstate success and errors", func(t *testing.T) {
		h := apiTestH(nil)
		st := injiDelegTokenStore(t)
		h.TokenStore = st
		idx, _ := st.Allocate()
		rr, m := injiDelegDo(h, h.APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"index": idx}))
		if rr.Code != http.StatusOK || m["revoked"] != float64(idx) || !st.IsRevoked(idx) {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		rr, m = injiDelegDo(h, h.APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"index": idx, "reinstate": true}))
		if rr.Code != http.StatusOK || m["reinstated"] != float64(idx) || st.IsRevoked(idx) {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		rr, _ = injiDelegDo(h, h.APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"index": -1}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "revoke:") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		rr, _ = injiDelegDo(h, h.APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"index": -1, "reinstate": true}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "reinstate:") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("bitstring kind resolves through the per-DPG set", func(t *testing.T) {
		h := apiTestH(nil)
		h.StatusLists = NewStatusListSet()
		fs := &slFakeStore{id: "bs1"}
		h.StatusLists.Register(&StatusListEntry{Store: fs, Kind: "bitstring", DPG: "Example DPG"})
		rr, m := injiDelegDo(h, h.APIInjiDelegationRevoke, authPOST(t, path, map[string]any{"index": 7, "type": "BitstringStatusList", "dpg": "Example DPG"}))
		if rr.Code != http.StatusOK || m["revoked"] != float64(7) || len(fs.revoked) != 1 || fs.revoked[0] != 7 {
			t.Fatalf("%d %s revoked=%v", rr.Code, rr.Body, fs.revoked)
		}
	})
}

// ─── verify endpoints ─────────────────────────────────────────────────────────

func TestVerifyInjiDelegation(t *testing.T) {
	h := &H{Sessions: NewStore()}
	get := func(cookies []*http.Cookie) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/holder/wallet/inji/verify-delegation", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr, m := injiDelegDo(h, h.VerifyInjiDelegation, req)
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		return m
	}
	if m := get(seedSession(t, h, nil)); m["credentialCount"] != float64(0) || m["valid"] != false || m["delegation"] != nil {
		t.Fatalf("empty wallet = %v", m)
	}
	sd := injiDelegSDJWT(t, "Person")
	if m := get(seedSession(t, h, func(s *Session) { s.InjiClaimedVCs = []string{sd} })); m["credentialCount"] != float64(1) || m["valid"] != true || m["delegation"] != nil {
		t.Fatalf("plain credential = %v", m)
	}
	m := get(seedSession(t, h, func(s *Session) { s.InjiClaimedVCs = []string{injiDelegLDCred(), sd} }))
	d, _ := m["delegation"].(map[string]any)
	if m["credentialCount"] != float64(2) || d == nil || d["Evaluated"] != true {
		t.Fatalf("delegation = %v", m)
	}
}

func TestVerifyWalletDelegation(t *testing.T) {
	get := func(h *H) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, "/holder/wallet/verify-delegation", nil)
		for _, c := range seedSession(t, h, nil) {
			req.AddCookie(c)
		}
		return injiDelegDo(h, h.VerifyWalletDelegation, req)
	}
	rr, _ := get(&H{Sessions: NewStore(), Adapter: &walletAdapter{credsErr: errors.New("wallet down")}})
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "list wallet credentials: wallet down") {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	rr, m := get(&H{Sessions: NewStore(), Adapter: &walletAdapter{creds: []vctypes.Credential{
		{Type: "Person", Issuer: "did:web:issuer.example", Fields: map[string]string{"subjectRef": "urn:person:1"}},
	}}})
	if rr.Code != http.StatusOK || m["credentialCount"] != float64(1) || m["valid"] != true || m["delegation"] != nil {
		t.Fatalf("%d %v", rr.Code, m)
	}
	rr, m = get(&H{Sessions: NewStore(), Adapter: &walletAdapter{creds: []vctypes.Credential{
		{Type: "DelegatedAccessCredential", Issuer: "did:web:issuer.example", Fields: map[string]string{"onBehalfOf": "urn:person:1", "allowedAction": "present"}},
	}}})
	d, _ := m["delegation"].(map[string]any)
	if rr.Code != http.StatusOK || d == nil || d["Evaluated"] != true {
		t.Fatalf("%d %v", rr.Code, m)
	}
}

func TestAPIVerifyDelegationSDJWT(t *testing.T) {
	path := "/api/v1/delegation/verify/sdjwt"
	rr, _ := injiDelegDo(nil, (&H{}).APIVerifyDelegationSDJWT, httptest.NewRequest(http.MethodPost, path, nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	req := authPOST(t, path, nil)
	req.Body = io.NopCloser(strings.NewReader("nope"))
	if rr, _ = injiDelegDo(nil, apiTestH(nil).APIVerifyDelegationSDJWT, req); rr.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	h := apiTestH(nil)
	rr, m := injiDelegDo(h, h.APIVerifyDelegationSDJWT, authPOST(t, path, map[string]any{"credentials": []string{
		"", injiDelegSDJWT(t, "Person"), "bad~sdjwt", "{}", `"str"`, injiDelegLDCred(),
	}}))
	d, _ := m["delegation"].(map[string]any)
	if rr.Code != http.StatusOK || m["credentialCount"] != float64(2) || d == nil || d["Evaluated"] != true {
		t.Fatalf("%d %v", rr.Code, m)
	}
	rr, m = injiDelegDo(h, h.APIVerifyDelegationSDJWT, authPOST(t, path, map[string]any{"credentials": []string{}}))
	if rr.Code != http.StatusOK || m["credentialCount"] != float64(0) || m["valid"] != false || m["delegation"] != nil {
		t.Fatalf("%d %v", rr.Code, m)
	}
}

// ─── pre-auth issue ───────────────────────────────────────────────────────────

func TestAPIInjiPreAuthDelegationIssue(t *testing.T) {
	path := "/api/v1/delegation/inji/preauth/issue"
	t.Run("unauthenticated", func(t *testing.T) {
		rr, _ := injiDelegDo(nil, (&H{}).APIInjiPreAuthDelegationIssue, httptest.NewRequest(http.MethodPost, path, nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		req := authPOST(t, path, nil)
		req.Body = io.NopCloser(strings.NewReader("{"))
		if rr, _ := injiDelegDo(nil, apiTestH(nil).APIInjiPreAuthDelegationIssue, req); rr.Code != http.StatusBadRequest {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("subject schema save error", func(t *testing.T) {
		h := apiTestH(&delegAPIAdapter{saveErr: errors.New("schema store down")})
		rr, _ := injiDelegDo(h, h.APIInjiPreAuthDelegationIssue, authPOST(t, path, map[string]any{}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "register subject schema: schema store down") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("delegation schema save error after tolerated 409 on the subject", func(t *testing.T) {
		ad := &injiDelegSaveAdapter{errs: []error{errors.New("409 conflict: already exists"), errors.New("hard fail")}}
		h := apiTestH(ad)
		rr, _ := injiDelegDo(h, h.APIInjiPreAuthDelegationIssue, authPOST(t, path, map[string]any{}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "register delegation schema: hard fail") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("status list allocate error", func(t *testing.T) {
		h := apiTestH(&delegAPIAdapter{})
		h.TokenStore = &slFakeStore{allocErr: errors.New("full")}
		rr, _ := injiDelegDo(h, h.APIInjiPreAuthDelegationIssue, authPOST(t, path, map[string]any{}))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "status list: status list allocate: full") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("subject issue error", func(t *testing.T) {
		h := apiTestH(&delegAPIAdapter{issueErr: errors.New("certify down")})
		rr, _ := injiDelegDo(h, h.APIInjiPreAuthDelegationIssue, authPOST(t, path, map[string]any{}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "issue subject: certify down") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("delegation issue error", func(t *testing.T) {
		ad := &injiDelegSaveAdapter{issueErrs: []error{nil, errors.New("second fails")}}
		h := apiTestH(ad)
		rr, _ := injiDelegDo(h, h.APIInjiPreAuthDelegationIssue, authPOST(t, path, map[string]any{}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "issue delegation: second fails") {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
	})
	t.Run("success without a store (no binding) and CREDEBL ids", func(t *testing.T) {
		ad := &delegAPIAdapter{}
		h := apiTestH(ad)
		rr, m := injiDelegDo(h, h.APIInjiPreAuthDelegationIssue, authPOST(t, path, map[string]any{"dpg": "CREDEBL", "subjectType": "Person", "delegationType": "Guardianship"}))
		if rr.Code != http.StatusCreated || m["statusListIndex"] != nil {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		if m["subject"].(map[string]any)["offerUri"] != "openid-credential-offer://custom-da-person" || m["delegation"].(map[string]any)["type"] != "Guardianship" {
			t.Fatalf("out = %v", m)
		}
		if len(ad.issued) != 2 || ad.issued[1].SubjectData["statusUri"] != "" || ad.issued[1].SubjectData["role"] != "Mother" {
			t.Fatalf("issued = %+v", ad.issued)
		}
	})
	t.Run("success with token binding, validUntil and actions", func(t *testing.T) {
		ad := &delegAPIAdapter{}
		h := apiTestH(ad)
		h.TokenStore = injiDelegTokenStore(t)
		rr, m := injiDelegDo(h, h.APIInjiPreAuthDelegationIssue, authPOST(t, path, map[string]any{
			"validUntil": "2030-01-01", "allowedAction": []string{"present", "sign"}, "role": "Guardian", "subjectRef": "urn:person:1", "givenName": "Alex",
		}))
		if rr.Code != http.StatusCreated || m["statusListIndex"] != float64(0) || m["statusType"] != "token" {
			t.Fatalf("%d %s", rr.Code, rr.Body)
		}
		if len(ad.saved) != 2 || ad.saved[1].FieldsSpec[3].Name != "valid_until" || ad.saved[0].ID != "dapre-birthcertificate" {
			t.Fatalf("saved = %+v", ad.saved)
		}
		d := ad.issued[1].SubjectData
		if d["valid_until"] != "2030-01-01" || d["allowedAction"] != "present,sign" || d["statusIdx"] != "0" || d["statusType"] != "token" || d["onBehalfOf"] != "urn:person:1" {
			t.Fatalf("delegation claims = %v", d)
		}
		if ad.issued[0].SubjectData["givenName"] != "Alex" {
			t.Fatalf("subject claims = %v", ad.issued[0].SubjectData)
		}
	})
}

// injiDelegSaveAdapter returns scripted errors from successive SaveCustomSchema
// / IssueToWallet calls.
type injiDelegSaveAdapter struct {
	delegAPIAdapter
	errs      []error
	issueErrs []error
}

func (a *injiDelegSaveAdapter) SaveCustomSchema(ctx context.Context, s vctypes.Schema) error {
	i := len(a.saved)
	_ = a.delegAPIAdapter.SaveCustomSchema(ctx, s)
	if i < len(a.errs) {
		return a.errs[i]
	}
	return nil
}
func (a *injiDelegSaveAdapter) IssueToWallet(ctx context.Context, r backend.IssueRequest) (backend.IssueToWalletResult, error) {
	i := len(a.issued)
	res, _ := a.delegAPIAdapter.IssueToWallet(ctx, r)
	if i < len(a.issueErrs) && a.issueErrs[i] != nil {
		return backend.IssueToWalletResult{}, a.issueErrs[i]
	}
	return res, nil
}

// ─── pre-auth headless claim ──────────────────────────────────────────────────

// injiDelegIssuer is a scripted OID4VCI pre-auth issuer: offer, metadata,
// token and credential endpoints, each overridable per test.
type injiDelegIssuer struct {
	srv        *httptest.Server
	offer      map[string]any
	meta       map[string]any
	tokenBody  string
	credStatus []int    // per-call status codes
	credBodies []string // per-call bodies
	credCalls  int
	credReqs   []map[string]any
	tokenForm  map[string]string
	dropCred   int // credential call index (1-based) at which the connection is dropped
}

func injiDelegNewIssuer(t *testing.T) *injiDelegIssuer {
	t.Helper()
	is := &injiDelegIssuer{tokenBody: `{"access_token":"tok","c_nonce":"n1"}`, credStatus: []int{200}, credBodies: []string{`{"credential":"a.b.c~"}`}}
	mux := http.NewServeMux()
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	is.offer = map[string]any{
		"credential_issuer": is.srv.URL, "credential_configuration_ids": []string{"cfg"},
		"grants": map[string]any{"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{"pre-authorized_code": "PAC"}},
	}
	is.meta = map[string]any{
		"credential_configurations_supported": map[string]any{"cfg": map[string]any{"format": "vc+sd-jwt", "vct": "Person"}},
	}
	mux.HandleFunc("/offer", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(is.offer) })
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(is.meta) })
	mux.HandleFunc("/v1/certify/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		is.tokenForm = map[string]string{}
		for k := range r.PostForm {
			is.tokenForm[k] = r.PostForm.Get(k)
		}
		_, _ = io.WriteString(w, is.tokenBody)
	})
	mux.HandleFunc("/v1/certify/issuance/credential", func(w http.ResponseWriter, r *http.Request) {
		is.credCalls++
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		is.credReqs = append(is.credReqs, m)
		if is.dropCred == is.credCalls {
			c, _, _ := w.(http.Hijacker).Hijack()
			_ = c.(net.Conn).Close()
			return
		}
		i := is.credCalls - 1
		if i >= len(is.credStatus) {
			i = len(is.credStatus) - 1
		}
		w.WriteHeader(is.credStatus[i])
		_, _ = io.WriteString(w, is.credBodies[i])
	})
	return is
}

func TestInjiPreAuthClaim(t *testing.T) {
	h := &H{}
	ctx := context.Background()
	t.Run("offer resolve error", func(t *testing.T) {
		_, err := h.injiPreAuthClaim(ctx, "http://127.0.0.1:1/offer", "")
		if err == nil || !strings.HasPrefix(err.Error(), "resolve offer: ") {
			t.Fatal(err)
		}
	})
	t.Run("offer without config ids / pre-auth code", func(t *testing.T) {
		is := injiDelegNewIssuer(t)
		is.offer["credential_configuration_ids"] = []string{}
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil || err.Error() != "offer has no credential_configuration_ids" {
			t.Fatal(err)
		}
		is.offer["credential_configuration_ids"] = []string{"cfg"}
		is.offer["grants"] = map[string]any{}
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil || err.Error() != "offer has no pre-authorized_code" {
			t.Fatal(err)
		}
	})
	t.Run("metadata error", func(t *testing.T) {
		is := injiDelegNewIssuer(t)
		is.offer["credential_issuer"] = "http://127.0.0.1:1/"
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil || !strings.HasPrefix(err.Error(), "issuer metadata: ") {
			t.Fatal(err)
		}
	})
	t.Run("token transport error and token denial", func(t *testing.T) {
		is := injiDelegNewIssuer(t)
		is.meta["token_endpoint"] = "http://127.0.0.1:1/token"
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil || !strings.HasPrefix(err.Error(), "pre-auth token: ") {
			t.Fatal(err)
		}
		delete(is.meta, "token_endpoint")
		is.tokenBody = `{"error":"invalid_grant","error_description":"expired"}`
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", "1234"); err == nil || err.Error() != "pre-auth token: invalid_grant expired" {
			t.Fatal(err)
		}
		if is.tokenForm["tx_code"] != "1234" || is.tokenForm["pre-authorized_code"] != "PAC" {
			t.Fatalf("token form = %v", is.tokenForm)
		}
	})
	t.Run("sd-jwt happy path via credential_offer_uri wrapper", func(t *testing.T) {
		is := injiDelegNewIssuer(t)
		vc, err := h.injiPreAuthClaim(ctx, "openid-credential-offer://?credential_offer_uri="+is.srv.URL+"/offer", "")
		if err != nil || vc != "a.b.c~" {
			t.Fatalf("vc=%q err=%v", vc, err)
		}
		req := is.credReqs[0]
		if req["vct"] != "Person" || req["format"] != "vc+sd-jwt" || is.tokenForm["tx_code"] != "" {
			t.Fatalf("credential request = %v", req)
		}
		proof := req["proof"].(map[string]any)["jwt"].(string)
		hdrRaw, _ := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[0])
		var hdr map[string]any
		_ = json.Unmarshal(hdrRaw, &hdr)
		if hdr["typ"] != "openid4vci-proof+jwt" || hdr["jwk"] == nil || hdr["kid"] != nil {
			t.Fatalf("proof header = %v", hdr)
		}
	})
	t.Run("ldp_vc with credential_definition; object credential returned raw", func(t *testing.T) {
		is := injiDelegNewIssuer(t)
		is.meta["credential_configurations_supported"] = map[string]any{"cfg": map[string]any{"format": "ldp_vc", "credential_definition": map[string]any{"type": []string{"Person"}}}}
		is.credBodies = []string{`{"credential":{"type":["Person"]}}`}
		vc, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", "")
		if err != nil || vc != `{"type":["Person"]}` {
			t.Fatalf("vc=%q err=%v", vc, err)
		}
		if is.credReqs[0]["credential_definition"] == nil || is.credReqs[0]["vct"] != nil {
			t.Fatalf("credential request = %v", is.credReqs[0])
		}
		// non-object credential_definition is skipped; non-JSON body returned verbatim
		is.meta["credential_configurations_supported"] = map[string]any{"cfg": map[string]any{"format": "ldp_vc", "credential_definition": "just-a-string"}}
		is.credBodies = []string{"raw-token"}
		is.credReqs = nil
		vc, err = h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", "")
		if err != nil || vc != "raw-token" || is.credReqs[0]["credential_definition"] != nil {
			t.Fatalf("vc=%q err=%v req=%v", vc, err, is.credReqs[0])
		}
	})
	t.Run("unknown config falls back to vc+sd-jwt without vct", func(t *testing.T) {
		is := injiDelegNewIssuer(t)
		is.meta["credential_configurations_supported"] = map[string]any{}
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err != nil {
			t.Fatal(err)
		}
		if is.credReqs[0]["format"] != "vc+sd-jwt" || is.credReqs[0]["vct"] != nil {
			t.Fatalf("credential request = %v", is.credReqs[0])
		}
	})
	t.Run("c_nonce retry then success; retry failure; transport errors", func(t *testing.T) {
		is := injiDelegNewIssuer(t)
		is.credStatus = []int{400, 200}
		is.credBodies = []string{`{"c_nonce":"n2"}`, `{"credential":"x~"}`}
		vc, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", "")
		if err != nil || vc != "x~" || is.credCalls != 2 {
			t.Fatalf("vc=%q err=%v calls=%d", vc, err, is.credCalls)
		}
		is = injiDelegNewIssuer(t)
		is.credStatus = []int{400, 403}
		is.credBodies = []string{`{"c_nonce":"n2"}`, `denied`}
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil || err.Error() != "credential endpoint 403: denied" {
			t.Fatal(err)
		}
		is = injiDelegNewIssuer(t)
		is.credStatus = []int{500}
		is.credBodies = []string{`{"error":"x"}`}
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil || !strings.HasPrefix(err.Error(), "credential endpoint 500: ") {
			t.Fatal(err)
		}
		is = injiDelegNewIssuer(t)
		is.dropCred = 1
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil {
			t.Fatal("dropped first credential call must error")
		}
		is = injiDelegNewIssuer(t)
		is.credStatus = []int{400}
		is.credBodies = []string{`{"c_nonce":"n2"}`}
		is.dropCred = 2
		if _, err := h.injiPreAuthClaim(ctx, is.srv.URL+"/offer", ""); err == nil || is.credCalls != 2 {
			t.Fatalf("dropped retry must error: err=%v calls=%d", err, is.credCalls)
		}
	})
}

func TestAPIInjiPreAuthDelegationClaim(t *testing.T) {
	path := "/api/v1/delegation/inji/preauth/claim"
	rr, _ := injiDelegDo(nil, (&H{}).APIInjiPreAuthDelegationClaim, httptest.NewRequest(http.MethodPost, path, nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	req := authPOST(t, path, nil)
	req.Body = io.NopCloser(strings.NewReader("{"))
	if rr, _ = injiDelegDo(nil, apiTestH(nil).APIInjiPreAuthDelegationClaim, req); rr.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	h := apiTestH(nil)
	rr, _ = injiDelegDo(h, h.APIInjiPreAuthDelegationClaim, authPOST(t, path, map[string]any{"offers": []string{"http://127.0.0.1:1/offer"}}))
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "claim offer 0: resolve offer: ") {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	a, b := injiDelegNewIssuer(t), injiDelegNewIssuer(t)
	b.credBodies = []string{`{"credential":"second~"}`}
	rr, m := injiDelegDo(h, h.APIInjiPreAuthDelegationClaim, authPOST(t, path, map[string]any{
		"offers": []string{a.srv.URL + "/offer", b.srv.URL + "/offer"}, "txCode": "0000", "txCodes": []string{"1111"},
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	creds, _ := m["credentials"].([]any)
	if len(creds) != 2 || creds[0] != "a.b.c~" || creds[1] != "second~" {
		t.Fatalf("credentials = %v", m)
	}
	if a.tokenForm["tx_code"] != "1111" || b.tokenForm["tx_code"] != "0000" {
		t.Fatalf("tx codes: a=%v b=%v", a.tokenForm, b.tokenForm)
	}
}
