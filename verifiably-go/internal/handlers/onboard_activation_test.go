package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// onboardSubjects wraps fakeSubjects so GetIdentity can fail (on the Nth call).
type onboardSubjects struct {
	*fakeSubjects
	getErr      error
	failOnCall  int // 0 = never; N = the Nth GetIdentity call returns getErr
	getCalls    int
	emptyOnCall int // N = the Nth GetIdentity call returns (nil, nil)
}

func (o *onboardSubjects) GetIdentity(ctx context.Context, id string) (map[string]string, error) {
	o.getCalls++
	if o.failOnCall == o.getCalls {
		return nil, o.getErr
	}
	if o.emptyOnCall == o.getCalls {
		return nil, nil
	}
	return o.fakeSubjects.GetIdentity(ctx, id)
}

func onboardIdentity(extra map[string]string) *fakeSubjects {
	rec := map[string]string{"individualId": "5550001", "email": "holder@example.org"}
	for k, v := range extra {
		rec[k] = v
	}
	return &fakeSubjects{identities: map[string]map[string]string{"5550001": rec}}
}

func onboardRequestStep(t *testing.T, h *H, id string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.RegisterHolder(rr, postFormReq(http.MethodPost, "/holder/register",
		url.Values{"step": {"request"}, "individual_id": {id}}))
	return rr
}

func onboardVerifyStep(t *testing.T, h *H, cookies []*http.Cookie, otp, pin string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.RegisterHolder(rr, formPost("/holder/register", url.Values{"step": {"verify"}, "otp": {otp}, "pin": {pin}}, cookies...))
	return rr
}

func TestMockIdentityURL(t *testing.T) {
	t.Setenv("MOCK_IDENTITY_URL", "")
	if got := mockIdentityURL(); got != "http://injiweb-mock-identity:8082" {
		t.Errorf("default = %q", got)
	}
	t.Setenv("MOCK_IDENTITY_URL", " http://mock.example/ ")
	if got := mockIdentityURL(); got != "http://mock.example" {
		t.Errorf("env = %q, want trimmed without trailing slash", got)
	}
}

func TestCreateMockIdentity_TransportErrors(t *testing.T) {
	t.Setenv("MOCK_IDENTITY_URL", "http://bad host")
	if err := createMockIdentity(context.Background(), "1", "123456", "A", "", "", "", "", "a@example.org", ""); err == nil {
		t.Fatal("invalid base URL must fail request construction")
	}
	t.Setenv("MOCK_IDENTITY_URL", "http://127.0.0.1:1")
	if err := createMockIdentity(context.Background(), "1", "123456", "A", "", "", "", "", "a@example.org", ""); err == nil {
		t.Fatal("unreachable identity system must return the transport error")
	}
}

func TestShowHolderRegister(t *testing.T) {
	h := activationH(t, &fakeSubjects{}, &fakeMailer{})
	cookies := seedSession(t, h, func(s *Session) { s.ActivationToken = "stale" })
	req := htmxMainRequest(http.MethodGet, "/holder/register")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ShowHolderRegister(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `name="individual_id"`) {
		t.Errorf("step-1 form missing individual_id input\n%s", rr.Body.String())
	}
	if got := h.Sessions.Get(req).ActivationToken; got != "" {
		t.Errorf("a fresh visit must clear ActivationToken, got %q", got)
	}

	if strings.Contains(rr.Body.String(), "Activation is not enabled") || strings.Contains(rr.Body.String(), "disabled>") {
		t.Errorf("enabled deployment must not show the disabled notice\n%s", rr.Body.String())
	}

	// Disabled deployment (no Subjects, no Mailer): the notice + disabled submit.
	h2 := &H{Sessions: NewStore(), Templates: loadPageTemplate(t, "holder_register")}
	rr2 := httptest.NewRecorder()
	h2.ShowHolderRegister(rr2, htmxMainRequest(http.MethodGet, "/holder/register"))
	if rr2.Code != http.StatusOK || !strings.Contains(rr2.Body.String(), "Activation is not enabled on this deployment.") ||
		!strings.Contains(rr2.Body.String(), "disabled>") {
		t.Errorf("disabled: status=%d, expected the not-enabled notice and a disabled submit\n%s", rr2.Code, rr2.Body.String())
	}
}

func TestActivateRequest_Errors(t *testing.T) {
	t.Run("empty id", func(t *testing.T) {
		h := activationH(t, onboardIdentity(nil), &fakeMailer{})
		rr := onboardRequestStep(t, h, "  ")
		if !strings.Contains(rr.Body.String(), "Enter your Individual ID.") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("lookup failure", func(t *testing.T) {
		s := &onboardSubjects{fakeSubjects: onboardIdentity(nil), getErr: errors.New("registry down"), failOnCall: 1}
		h := activationH(t, &fakeSubjects{}, &fakeMailer{})
		h.Subjects = s
		rr := onboardRequestStep(t, h, "5550001")
		if !strings.Contains(rr.Body.String(), "Identity lookup failed: registry down") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("no email on file", func(t *testing.T) {
		f := onboardIdentity(map[string]string{"email": " "})
		m := &fakeMailer{}
		h := activationH(t, f, m)
		rr := onboardRequestStep(t, h, "5550001")
		if !strings.Contains(rr.Body.String(), "no email on file") || m.sent != 0 {
			t.Errorf("sent=%d body=%s", m.sent, rr.Body.String())
		}
	})
	t.Run("mailer not configured", func(t *testing.T) {
		h := activationH(t, onboardIdentity(nil), nil)
		rr := onboardRequestStep(t, h, "5550001")
		if !strings.Contains(rr.Body.String(), "Email delivery isn") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("send failure", func(t *testing.T) {
		m := &fakeMailer{err: errors.New("smtp refused")}
		h := activationH(t, onboardIdentity(nil), m)
		rr := onboardRequestStep(t, h, "5550001")
		if !strings.Contains(rr.Body.String(), "Couldn") || !strings.Contains(rr.Body.String(), "send the verification email") {
			t.Errorf("body=%s", rr.Body.String())
		}
		probe := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range rr.Result().Cookies() {
			probe.AddCookie(c)
		}
		if tok := h.Sessions.Get(probe).ActivationToken; tok != "" {
			t.Errorf("token must not be stored when the email failed")
		}
	})
}

func TestActivateVerify_Errors(t *testing.T) {
	t.Setenv("VERIFIABLY_REGISTRIES", "")
	t.Run("no activation in session", func(t *testing.T) {
		h := activationH(t, onboardIdentity(nil), &fakeMailer{})
		rr := onboardVerifyStep(t, h, nil, "123456", "123456")
		if !strings.Contains(rr.Body.String(), "activation session expired") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("unknown token", func(t *testing.T) {
		h := activationH(t, onboardIdentity(nil), &fakeMailer{})
		cookies := seedSession(t, h, func(s *Session) { s.ActivationToken = "not-issued" })
		rr := onboardVerifyStep(t, h, cookies, "123456", "123456")
		if !strings.Contains(rr.Body.String(), "verification code expired") {
			t.Errorf("body=%s", rr.Body.String())
		}
		probe := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			probe.AddCookie(c)
		}
		if h.Sessions.Get(probe).ActivationToken != "" {
			t.Error("a dead token must be cleared from the session")
		}
	})

	// Shared happy step-1 for the remaining cases.
	start := func(t *testing.T, h *H, m *fakeMailer) ([]*http.Cookie, string) {
		t.Helper()
		rr := onboardRequestStep(t, h, "5550001")
		if m.sent != 1 {
			t.Fatalf("step1 sent=%d body=%s", m.sent, rr.Body.String())
		}
		return rr.Result().Cookies(), m.code()
	}
	t.Run("missing otp or pin", func(t *testing.T) {
		m := &fakeMailer{}
		h := activationH(t, onboardIdentity(nil), m)
		cookies, code := start(t, h, m)
		rr := onboardVerifyStep(t, h, cookies, code, "")
		if !strings.Contains(rr.Body.String(), "Enter the code we emailed and choose a PIN.") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("short pin", func(t *testing.T) {
		m := &fakeMailer{}
		h := activationH(t, onboardIdentity(nil), m)
		cookies, code := start(t, h, m)
		rr := onboardVerifyStep(t, h, cookies, code, "123")
		if !strings.Contains(rr.Body.String(), "PIN must be at least 6 digits") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("identity vanished after verify", func(t *testing.T) {
		m := &fakeMailer{}
		s := &onboardSubjects{fakeSubjects: onboardIdentity(nil), emptyOnCall: 2}
		h := activationH(t, &fakeSubjects{}, m)
		h.Subjects = s
		cookies, code := start(t, h, m)
		rr := onboardVerifyStep(t, h, cookies, code, "123456")
		if !strings.Contains(rr.Body.String(), "identity record could not be read") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("identity system unreachable", func(t *testing.T) {
		t.Setenv("MOCK_IDENTITY_URL", "http://127.0.0.1:1")
		m := &fakeMailer{}
		h := activationH(t, onboardIdentity(map[string]string{"givenName": "Ada", "familyName": "Lovelace"}), m)
		cookies, code := start(t, h, m)
		rr := onboardVerifyStep(t, h, cookies, code, "123456")
		if !strings.Contains(rr.Body.String(), "Create identity:") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
	t.Run("provision failure", func(t *testing.T) {
		srv := onboardServer(t)
		defer srv.Close()
		t.Setenv("MOCK_IDENTITY_URL", srv.URL)
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"reg","url":"`+srv.URL+`","discover":true}]`)
		m := &fakeMailer{}
		f := onboardIdentity(map[string]string{"fullName": "Ada Lovelace"})
		f.provErr = errors.New("write failed")
		h := activationH(t, f, m)
		cookies, code := start(t, h, m)
		rr := onboardVerifyStep(t, h, cookies, code, "123456")
		if !strings.Contains(rr.Body.String(), "Save registry data: write failed") {
			t.Errorf("body=%s", rr.Body.String())
		}
	})
}

// A legacy GET-by-id registry (no entity, no discover) yields flat claims —
// they are provisioned un-namespaced.
func TestActivateVerify_LegacyRegistryKeepsFlatClaims(t *testing.T) {
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/mock-identity-system/identity":
			_, _ = w.Write([]byte(`{"response":{}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/records/5550001":
			_, _ = w.Write([]byte(`{"fullName":"Ada Lovelace","osid":"x"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer reg.Close()
	t.Setenv("MOCK_IDENTITY_URL", reg.URL)
	t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"legacy","url":"`+reg.URL+`","path":"/records/"}]`)
	t.Setenv("INJI_AUTHCODE_CLIENT_ID", "")

	m := &fakeMailer{}
	f := onboardIdentity(map[string]string{"givenName": "Ada", "familyName": "Lovelace"})
	h := activationH(t, f, m)
	rr1 := onboardRequestStep(t, h, "5550001")
	if m.sent != 1 {
		t.Fatalf("step1 sent=%d body=%s", m.sent, rr1.Body.String())
	}
	rr := onboardVerifyStep(t, h, rr1.Result().Cookies(), m.code(), "123456")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "activated") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(f.provCalls) != 1 {
		t.Fatalf("provCalls = %d", len(f.provCalls))
	}
	if c := f.provCalls[0].claims; c["fullName"] != "Ada Lovelace" {
		t.Errorf("legacy claims must stay flat: %v", c)
	}
	// fullName was absent from the registry record → derived from given+family.
	if !strings.Contains(rr.Body.String(), "Ada Lovelace") {
		t.Errorf("success page should show the derived full name\n%s", rr.Body.String())
	}
}
