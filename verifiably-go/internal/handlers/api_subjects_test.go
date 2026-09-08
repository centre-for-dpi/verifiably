package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultAuthCodeClientID(t *testing.T) {
	t.Setenv("VERIFIABLY_AUTHCODE_CLIENT_ID", "  ")
	if got := defaultAuthCodeClientID(); got != "wallet-demo-client" {
		t.Errorf("blank env: got %q", got)
	}
	t.Setenv("VERIFIABLY_AUTHCODE_CLIENT_ID", " my-client ")
	if got := defaultAuthCodeClientID(); got != "my-client" {
		t.Errorf("env set: got %q", got)
	}
}

func TestAPIProvisionSubject_Guards(t *testing.T) {
	t.Setenv("VERIFIABLY_AUTHCODE_CLIENT_ID", "")
	t.Run("unauthenticated", func(t *testing.T) {
		h := apiTestH(&testAdapter{})
		h.Subjects = &fakeSubjects{}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/subjects", strings.NewReader(`{}`))
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
	t.Run("subjects not enabled", func(t *testing.T) {
		h := apiTestH(&testAdapter{})
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, authPOST(t, "/api/v1/subjects", map[string]any{"individualId": "1"}))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "not enabled") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	h := apiTestH(&testAdapter{})
	f := &fakeSubjects{}
	h.Subjects = f
	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/subjects", strings.NewReader(`{oops`))
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid JSON") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("individualId required", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, authPOST(t, "/api/v1/subjects", map[string]any{"individualId": "  ", "fullName": "x"}))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "individualId required") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("at least one claim", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, authPOST(t, "/api/v1/subjects", map[string]any{
			"individualId": "123", "fullName": "  ", "claims": map[string]string{"x": " "}}))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "at least one claim") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
		if len(f.provCalls) != 0 {
			t.Errorf("must not provision without claims")
		}
	})
	t.Run("provision failure", func(t *testing.T) {
		f.provErr = errors.New("db down")
		defer func() { f.provErr = nil }()
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, authPOST(t, "/api/v1/subjects", map[string]any{"individualId": "123", "email": "a@example.org"}))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "provision failed: db down") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestAPIProvisionSubject_Success(t *testing.T) {
	t.Setenv("VERIFIABLY_AUTHCODE_CLIENT_ID", "")
	h := apiTestH(&testAdapter{})
	f := &fakeSubjects{}
	h.Subjects = f

	t.Run("default client, flat claims", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, authPOST(t, "/api/v1/subjects", map[string]any{
			"individualId": " 9090 ", "fullName": " Grace Hopper ", "givenName": "Grace", "familyName": "Hopper",
			"gender": "F", "dateOfBirth": "1906-12-09", "email": "grace@example.org", "phoneNumber": "+1555",
			"claims": map[string]string{"role": "admin", "blank": ""},
		}))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
		}
		got := decodeJSON(t, rr.Body.Bytes())
		want := esignetSubjectID("9090", "wallet-demo-client")
		if got["individualId"] != "9090" || got["clientId"] != "wallet-demo-client" || got["subjectId"] != want {
			t.Errorf("response = %v", got)
		}
		if len(f.provCalls) != 1 || f.provCalls[0].subjectID != want {
			t.Fatalf("provCalls = %+v", f.provCalls)
		}
		c := f.provCalls[0].claims
		if c["fullName"] != "Grace Hopper" || c["givenName"] != "Grace" || c["familyName"] != "Hopper" || c["gender"] != "F" ||
			c["dateOfBirth"] != "1906-12-09" || c["email"] != "grace@example.org" || c["phoneNumber"] != "+1555" || c["role"] != "admin" {
			t.Errorf("claims = %v", c)
		}
		if _, has := c["blank"]; has {
			t.Errorf("blank claim must be dropped: %v", c)
		}
	})
	t.Run("explicit client + namespaced claims", func(t *testing.T) {
		f.provCalls = nil
		rr := httptest.NewRecorder()
		h.APIProvisionSubject(rr, authPOST(t, "/api/v1/subjects", map[string]any{
			"individualId": "77", "clientId": " other-client ", "credentialConfigKey": "PersonCredential",
			"claims": map[string]string{"role": "admin"},
		}))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
		}
		got := decodeJSON(t, rr.Body.Bytes())
		if got["clientId"] != "other-client" || got["subjectId"] != esignetSubjectID("77", "other-client") {
			t.Errorf("response = %v", got)
		}
		c := f.provCalls[0].claims
		wantKey := subjectClaimKey(slugForEntity(nil, "PersonCredential"), "role")
		if c[wantKey] != "admin" {
			t.Errorf("claims = %v, want key %q", c, wantKey)
		}
	})
}
