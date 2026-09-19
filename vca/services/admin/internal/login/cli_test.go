// SPDX-License-Identifier: Apache-2.0

package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
)

// post sends a form to one path of the login server.
func (h *harness) post(t *testing.T, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	res, err := h.client.Post(h.server.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer res.Body.Close()
	body := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func TestDeviceAuthorizationProxiesTheProvider(t *testing.T) {
	h := newHarness(t)
	id := h.deviceProvider(t)
	status, body := h.post(t, "/device_authorization", url.Values{"provider": {id}})
	if status != http.StatusOK {
		t.Fatalf("status = %d body = %v", status, body)
	}
	if body["device_code"] != "device-code-1" || body["user_code"] != "ABCD-EFGH" {
		t.Fatalf("body = %v", body)
	}
	if body["provider"] != id {
		t.Errorf("provider = %v", body["provider"])
	}
}

func TestDeviceAuthorizationRefusesAProviderWithoutTheGrant(t *testing.T) {
	h := newHarness(t)
	id := h.deviceProvider(t)
	h.device.noDevice = true
	status, body := h.post(t, "/device_authorization", url.Values{"provider": {id}})
	if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("status = %d body = %v", status, body)
	}
}

func TestDeviceAuthorizationRefusesAnUnknownProvider(t *testing.T) {
	h := newHarness(t)
	status, _ := h.post(t, "/device_authorization", url.Values{"provider": {"nope"}})
	if status != http.StatusNotFound {
		t.Fatalf("status = %d", status)
	}
}

func TestDeviceAuthorizationRefusesADisabledProvider(t *testing.T) {
	h := newHarness(t)
	id := h.deviceProvider(t)
	p, err := h.svc.Providers().Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	p.Enabled = false
	if _, err := h.svc.Providers().Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}
	status, _ := h.post(t, "/device_authorization", url.Values{"provider": {id}})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
}

func TestTokenEndpointReturnsAnAdminSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id := h.deviceProvider(t)
	token := records.NewBootstrapToken()
	if err := h.rec.SetBootstrap(ctx, token); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	status, body := h.post(t, "/token", url.Values{
		"provider": {id}, "grant_type": {login.DeviceGrant},
		"device_code": {"device-code-1"}, login.BootstrapField: {token},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d body = %v", status, body)
	}
	session, _ := body["access_token"].(string)
	if session == "" {
		t.Fatalf("body = %v", body)
	}
	claims, err := h.svc.Session(ctx, session)
	if err != nil || !claims.HasRole(login.RoleSuperAdmin) {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	if body["token_type"] != "Bearer" || body["csrf_token"] == "" {
		t.Errorf("body = %v", body)
	}
}

func TestTokenEndpointPassesAPendingAnswerThrough(t *testing.T) {
	h := newHarness(t)
	id := h.deviceProvider(t)
	status, body := h.post(t, "/token", url.Values{
		"provider": {id}, "grant_type": {login.DeviceGrant}, "device_code": {"other"},
	})
	if status != http.StatusBadRequest || body["error"] != "authorization_pending" {
		t.Fatalf("status = %d body = %v", status, body)
	}
}

func TestTokenEndpointChecksItsInput(t *testing.T) {
	h := newHarness(t)
	id := h.deviceProvider(t)
	if status, body := h.post(t, "/token", url.Values{"grant_type": {"password"}}); status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Errorf("password grant: %d %v", status, body)
	}
	if status, _ := h.post(t, "/token", url.Values{"grant_type": {login.DeviceGrant}}); status != http.StatusBadRequest {
		t.Error("a request without a device code was accepted")
	}
	if status, _ := h.post(t, "/token", url.Values{
		"grant_type": {login.DeviceGrant}, "device_code": {"x"}, "provider": {"nope"},
	}); status != http.StatusNotFound {
		t.Error("an unknown provider was accepted")
	}
	h.device.body = "not json"
	if status, _ := h.post(t, "/token", url.Values{
		"grant_type": {login.DeviceGrant}, "device_code": {"device-code-1"}, "provider": {id},
	}); status != http.StatusBadGateway {
		t.Error("a body that is not JSON was accepted")
	}
	h.device.body = `{"access_token":"at"}`
	if status, _ := h.post(t, "/token", url.Values{
		"grant_type": {login.DeviceGrant}, "device_code": {"device-code-1"}, "provider": {id},
	}); status != http.StatusBadGateway {
		t.Error("an answer without an id token was accepted")
	}
	h.device.body = `{"id_token":"broken"}`
	if status, _ := h.post(t, "/token", url.Values{
		"grant_type": {login.DeviceGrant}, "device_code": {"device-code-1"}, "provider": {id},
	}); status == http.StatusOK {
		t.Error("a broken id token was accepted")
	}
}

func TestTokenEndpointRefusesASubjectWithoutTheRole(t *testing.T) {
	h := newHarness(t)
	id := h.deviceProvider(t)
	status, body := h.post(t, "/token", url.Values{
		"provider": {id}, "grant_type": {login.DeviceGrant}, "device_code": {"device-code-1"},
	})
	if status == http.StatusOK {
		t.Fatalf("status = %d body = %v", status, body)
	}
}

func TestLoopbackLoginGivesASessionToTheCLI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := records.NewBootstrapToken()
	if err := h.rec.SetBootstrap(ctx, token); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	status, body := h.post(t, "/cli/login", url.Values{
		"provider": {"idp"}, "port": {"49152"}, login.BootstrapField: {token},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d body = %v", status, body)
	}
	authorizeURL, _ := body["authorization_url"].(string)
	if authorizeURL == "" || body["redirect_uri"] != login.LoopbackURL("49152", "") {
		t.Fatalf("body = %v", body)
	}
	back, err := h.idp.Authorize(authorizeURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	res, err := h.client.Get(back)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d", res.StatusCode)
	}
	location := res.Header.Get("Location")
	if !strings.HasPrefix(location, "http://127.0.0.1:49152/callback?code=") {
		t.Fatalf("location = %q", location)
	}
	// No token travels in the URL (RFC 9700 section 4.3.2).
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	code := parsed.Query().Get("code")
	status, body = h.post(t, "/cli/token", url.Values{"code": {code}})
	if status != http.StatusOK {
		t.Fatalf("token status = %d body = %v", status, body)
	}
	session, _ := body["access_token"].(string)
	claims, err := h.svc.Session(ctx, session)
	if err != nil || !claims.HasRole(login.RoleSuperAdmin) {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	// The code works once only.
	if status, _ := h.post(t, "/cli/token", url.Values{"code": {code}}); status != http.StatusBadRequest {
		t.Error("the one time code worked twice")
	}
}

func TestLoopbackLoginChecksThePort(t *testing.T) {
	h := newHarness(t)
	for _, port := range []string{"", "80", "notaport", "70000"} {
		if status, _ := h.post(t, "/cli/login", url.Values{"provider": {"idp"}, "port": {port}}); status != http.StatusBadRequest {
			t.Errorf("port %q was accepted", port)
		}
	}
	if status, _ := h.post(t, "/cli/login", url.Values{"provider": {"nope"}, "port": {"49152"}}); status != http.StatusNotFound {
		t.Error("an unknown provider was accepted")
	}
}

func TestLoopbackTokenRefusesAnUnknownCode(t *testing.T) {
	h := newHarness(t)
	for _, code := range []string{"", "nothing"} {
		if status, _ := h.post(t, "/cli/token", url.Values{"code": {code}}); status != http.StatusBadRequest {
			t.Errorf("code %q was accepted", code)
		}
	}
}

func TestCallbackOfACLILoginReportsAFailure(t *testing.T) {
	h := newHarness(t)
	status, body := h.post(t, "/cli/login", url.Values{"provider": {"idp"}, "port": {"49153"}})
	if status != http.StatusOK {
		t.Fatalf("status = %d body = %v", status, body)
	}
	authorizeURL, _ := body["authorization_url"].(string)
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	state := parsed.Query().Get("state")
	res, err := h.client.Get(h.server.URL + "/auth/callback?state=" + url.QueryEscape(state) + "&error=access_denied")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusSeeOther {
		t.Fatalf("a failed login redirected to the loopback")
	}
}

func TestValidPortAndLoopbackURL(t *testing.T) {
	if login.ValidPort("1023") || !login.ValidPort("1024") || !login.ValidPort("65535") {
		t.Error("ValidPort accepts the wrong range")
	}
	if got := login.LoopbackURL("5000", "a b"); got != "http://127.0.0.1:5000/callback?code=a+b" {
		t.Errorf("LoopbackURL = %q", got)
	}
}

func TestQueryTokensAreRejected(t *testing.T) {
	h := newHarness(t)
	res, err := h.client.Post(h.server.URL+"/token?access_token=leak", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", res.StatusCode)
	}
}
