package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// ─── mlValue ──────────────────────────────────────────────────────────────────

func TestMlValue(t *testing.T) {
	got := mlValue("Grace")
	want := []map[string]string{{"language": "eng", "value": "Grace"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mlValue = %v, want %v", got, want)
	}
}

// ─── createMockIdentity ────────────────────────────────────────────────────────

func TestCreateMockIdentity(t *testing.T) {
	call := func(t *testing.T, status int, body string) error {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/mock-identity-system/identity" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		defer srv.Close()
		t.Setenv("MOCK_IDENTITY_URL", srv.URL)
		return createMockIdentity(context.Background(), "9090", "111111", "Grace Hopper",
			"Grace", "Hopper", "", "", "grace@x.org", "+15551234567")
	}

	t.Run("success", func(t *testing.T) {
		if err := call(t, 200, `{"response":{"status":"ACTIVATED"}}`); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("already exists -> success (idempotent)", func(t *testing.T) {
		if err := call(t, 200, `{"errors":[{"errorCode":"IDR-001","errorMessage":"Identity already exists"}]}`); err != nil {
			t.Errorf("already-exists should be treated as success, got %v", err)
		}
	})
	t.Run("duplicate -> success (idempotent)", func(t *testing.T) {
		if err := call(t, 200, `{"errors":[{"errorCode":"DUP","errorMessage":"duplicate record"}]}`); err != nil {
			t.Errorf("duplicate should be treated as success, got %v", err)
		}
	})
	t.Run("genuine error surfaces", func(t *testing.T) {
		err := call(t, 200, `{"errors":[{"errorCode":"IDA-MLC-018","errorMessage":"invalid request"}]}`)
		if err == nil || !strings.Contains(err.Error(), "invalid request") {
			t.Errorf("want error mentioning the reason, got %v", err)
		}
	})
	t.Run("HTTP error with no errors body", func(t *testing.T) {
		err := call(t, 400, `{"response":null}`)
		if err == nil || !strings.Contains(err.Error(), "400") {
			t.Errorf("want HTTP 400 error, got %v", err)
		}
	})
}

// ─── RegisterHolder ────────────────────────────────────────────────────────────

// onboardServer is a single test server that plays both the eSignet
// mock-identity-system and a Sunbird (discover) registry, routed by path.
func onboardServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/mock-identity-system/identity":
			_, _ = io.WriteString(w, `{"response":{"status":"ACTIVATED"}}`)
		case "/api/v1/Schema/search":
			_, _ = io.WriteString(w, `{"data":[{"name":"TestEntity"}]}`)
		case "/api/v1/TestEntity/search":
			_, _ = io.WriteString(w, `{"data":[{"fullName":"Grace Hopper","dob":"1906","osid":"x","osOwner":"o","_osState":"s"}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func postFormReq(method, path string, form url.Values) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("HX-Target", "main")
	return req
}

func TestRegisterHolder_HappyPath(t *testing.T) {
	srv := onboardServer(t)
	defer srv.Close()
	t.Setenv("MOCK_IDENTITY_URL", srv.URL)
	t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"sunbird","url":"`+srv.URL+`","discover":true}]`)
	t.Setenv("INJI_AUTHCODE_CLIENT_ID", "") // default wallet-demo-client

	f := &fakeSubjects{}
	h := &H{Sessions: NewStore(), Subjects: f, Templates: loadPageTemplate(t, "holder_register")}

	form := url.Values{
		"individual_id": {"9876543210"},
		"given_name":    {"Grace"},
		"family_name":   {"Hopper"},
		"email":         {"grace@example.org"},
		"phone":         {"+15551234567"},
	}
	rr := httptest.NewRecorder()
	h.RegisterHolder(rr, postFormReq(http.MethodPost, "/holder/register", form))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(f.provCalls) != 1 {
		t.Fatalf("ProvisionSubject called %d times, want 1", len(f.provCalls))
	}
	got := f.provCalls[0]

	wantSubject := esignetSubjectID("9876543210", "wallet-demo-client")
	if got.subjectID != wantSubject {
		t.Errorf("subjectID = %q, want %q (eSignet PSU-token)", got.subjectID, wantSubject)
	}
	wantClaims := map[string]string{"fullName": "Grace Hopper", "dob": "1906"}
	if !reflect.DeepEqual(got.claims, wantClaims) {
		t.Errorf("claims = %v, want %v (os* stripped, merged from registry)", got.claims, wantClaims)
	}
	if !strings.Contains(rr.Body.String(), "Grace Hopper") {
		t.Errorf("success page should show the full name\nbody=%s", rr.Body.String())
	}
}

func TestRegisterHolder_MissingFields(t *testing.T) {
	srv := onboardServer(t)
	defer srv.Close()
	t.Setenv("MOCK_IDENTITY_URL", srv.URL)
	t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"sunbird","url":"`+srv.URL+`","discover":true}]`)

	f := &fakeSubjects{}
	h := &H{Sessions: NewStore(), Subjects: f, Templates: loadPageTemplate(t, "holder_register")}

	// Only individual_id supplied — given/family/email/phone are missing.
	form := url.Values{"individual_id": {"123"}}
	rr := httptest.NewRecorder()
	h.RegisterHolder(rr, postFormReq(http.MethodPost, "/holder/register", form))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (error renders inline)", rr.Code)
	}
	if len(f.provCalls) != 0 {
		t.Errorf("must NOT provision when required fields are missing; got %d calls", len(f.provCalls))
	}
	if !strings.Contains(rr.Body.String(), "required") {
		t.Errorf("expected a 'required' error message\nbody=%s", rr.Body.String())
	}
}

// TestRegisterHolder_Disabled renders the not-enabled notice when no subject
// provisioner is wired (Subjects == nil).
func TestRegisterHolder_Disabled(t *testing.T) {
	h := &H{Sessions: NewStore(), Templates: loadPageTemplate(t, "holder_register")}
	rr := httptest.NewRecorder()
	h.RegisterHolder(rr, postFormReq(http.MethodPost, "/holder/register", url.Values{}))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not enabled") {
		t.Errorf("expected 'not enabled' notice\nbody=%s", rr.Body.String())
	}
}
