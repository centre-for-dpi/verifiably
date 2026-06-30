package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
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

// ─── holder activation (registry-gated, email-OTP) ───────────────────────────

// onboardServer plays both the eSignet mock-identity-system and a Sunbird
// (discover) CREDENTIAL registry, routed by path. (The identity registry is the
// fakeSubjects store, separate from this credential registry.)
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

// fakeMailer captures the activation email so a test can read back the OTP.
type fakeMailer struct {
	to, subject, body string
	sent              int
	err               error
}

func (m *fakeMailer) Send(to, subject, body string) error {
	if m.err != nil {
		return m.err
	}
	m.to, m.subject, m.body = to, subject, body
	m.sent++
	return nil
}

var sixDigits = regexp.MustCompile(`\b(\d{6})\b`)

func (m *fakeMailer) code() string {
	if g := sixDigits.FindStringSubmatch(m.body); g != nil {
		return g[1]
	}
	return ""
}

func activationH(t *testing.T, f *fakeSubjects, m Mailer) *H {
	t.Helper()
	return &H{
		Sessions:  NewStore(),
		Subjects:  f,
		Mailer:    m,
		OTPs:      NewOTPStore(),
		Templates: loadPageTemplate(t, "holder_register"),
	}
}

// A holder who is NOT in the identity registry is refused — no email, no
// identity creation, no provisioning. This is the core gate.
func TestActivate_NotEnrolled(t *testing.T) {
	f := &fakeSubjects{} // empty identity registry
	m := &fakeMailer{}
	h := activationH(t, f, m)
	rr := httptest.NewRecorder()
	h.RegisterHolder(rr, postFormReq(http.MethodPost, "/holder/register",
		url.Values{"step": {"request"}, "individual_id": {"404404"}}))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if m.sent != 0 {
		t.Errorf("must not email an unenrolled id; sent=%d", m.sent)
	}
	if len(f.provCalls) != 0 {
		t.Errorf("must not provision an unenrolled id; calls=%d", len(f.provCalls))
	}
	if !strings.Contains(rr.Body.String(), "not enrolled") {
		t.Errorf("expected a 'not enrolled' refusal\nbody=%s", rr.Body.String())
	}
}

// Full two-step activation: step 1 emails the OTP to the on-file address; step 2
// (correct code + PIN) materialises the identity from REGISTRY demographics and
// provisions credential claims keyed by the PSU-token.
func TestActivate_HappyPath(t *testing.T) {
	srv := onboardServer(t)
	defer srv.Close()
	t.Setenv("MOCK_IDENTITY_URL", srv.URL)
	t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"sunbird","url":"`+srv.URL+`","discover":true}]`)
	t.Setenv("INJI_AUTHCODE_CLIENT_ID", "") // default wallet-demo-client

	f := &fakeSubjects{identities: map[string]map[string]string{
		"9876543210": {"individualId": "9876543210", "fullName": "Grace Hopper", "email": "grace@example.org", "phone": "+15551234567"},
	}}
	m := &fakeMailer{}
	h := activationH(t, f, m)

	// Step 1 — request.
	rr1 := httptest.NewRecorder()
	h.RegisterHolder(rr1, postFormReq(http.MethodPost, "/holder/register",
		url.Values{"step": {"request"}, "individual_id": {"9876543210"}}))
	if m.sent != 1 {
		t.Fatalf("step1 should email one OTP; sent=%d\nbody=%s", m.sent, rr1.Body.String())
	}
	if m.to != "grace@example.org" {
		t.Errorf("OTP emailed to %q, want the on-file address", m.to)
	}
	code := m.code()
	if code == "" {
		t.Fatalf("no 6-digit code in the email body: %q", m.body)
	}
	if len(f.provCalls) != 0 {
		t.Errorf("step1 must not provision yet; calls=%d", len(f.provCalls))
	}
	cookies := rr1.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("step1 set no session cookie")
	}

	// Step 2 — verify (carry the session cookie).
	rr2 := httptest.NewRecorder()
	req2 := postFormReq(http.MethodPost, "/holder/register",
		url.Values{"step": {"verify"}, "otp": {code}, "pin": {"123456"}})
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	h.RegisterHolder(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("step2 status = %d\nbody=%s", rr2.Code, rr2.Body.String())
	}
	if len(f.provCalls) != 1 {
		t.Fatalf("step2 should provision once; calls=%d\nbody=%s", len(f.provCalls), rr2.Body.String())
	}
	want := esignetSubjectID("9876543210", "wallet-demo-client")
	if f.provCalls[0].subjectID != want {
		t.Errorf("subjectID = %q, want %q (PSU-token)", f.provCalls[0].subjectID, want)
	}
	if c := f.provCalls[0].claims; c["fullName"] != "Grace Hopper" || c["dob"] != "1906" {
		t.Errorf("claims = %v, want registry-sourced {fullName,dob}", c)
	}
	if !strings.Contains(rr2.Body.String(), "Grace Hopper") || !strings.Contains(rr2.Body.String(), "activated") {
		t.Errorf("success page should confirm activation\nbody=%s", rr2.Body.String())
	}
}

// A wrong verification code does not activate or provision.
func TestActivate_WrongCode(t *testing.T) {
	f := &fakeSubjects{identities: map[string]map[string]string{
		"9876543210": {"fullName": "Grace Hopper", "email": "grace@example.org"},
	}}
	m := &fakeMailer{}
	h := activationH(t, f, m)
	rr1 := httptest.NewRecorder()
	h.RegisterHolder(rr1, postFormReq(http.MethodPost, "/holder/register",
		url.Values{"step": {"request"}, "individual_id": {"9876543210"}}))
	bad := "000000"
	if m.code() == bad {
		bad = "111111"
	}
	rr2 := httptest.NewRecorder()
	req2 := postFormReq(http.MethodPost, "/holder/register",
		url.Values{"step": {"verify"}, "otp": {bad}, "pin": {"123456"}})
	for _, c := range rr1.Result().Cookies() {
		req2.AddCookie(c)
	}
	h.RegisterHolder(rr2, req2)
	if len(f.provCalls) != 0 {
		t.Errorf("a wrong code must not activate/provision; calls=%d", len(f.provCalls))
	}
	if !strings.Contains(rr2.Body.String(), "Verification failed") {
		t.Errorf("expected a verification-failed message\nbody=%s", rr2.Body.String())
	}
}

// TestActivate_Disabled renders the not-enabled notice when no subject
// provisioner is wired (Subjects == nil).
func TestActivate_Disabled(t *testing.T) {
	h := &H{Sessions: NewStore(), OTPs: NewOTPStore(), Templates: loadPageTemplate(t, "holder_register")}
	rr := httptest.NewRecorder()
	h.RegisterHolder(rr, postFormReq(http.MethodPost, "/holder/register", url.Values{}))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not enabled") {
		t.Errorf("expected 'not enabled' notice\nbody=%s", rr.Body.String())
	}
}
