// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/service"
)

// withCallbacks wires the issuer with the callback URL.
var withCallbacks = roles{issuer: true, callbacks: true}

// offer creates one offer and returns its id and the callback path
// walt.id got in the statusCallbackUri header.
func offer(t *testing.T, svc *service.Service, f interface{ LastHeader(string) string }) (string, string) {
	t.Helper()
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "UniversityDegree_jwt_vc_json", SubjectData: `{"degree":"Mathematics"}`,
			Subject: &commonv1.Subject{Did: "did:key:zHolder"},
			Status:  &backendv1.StatusListBinding{Kind: backendv1.StatusListBinding_KIND_BITSTRING, Index: 7, PublishUrl: "https://status.example.org/bitstring/1"},
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	callback := f.LastHeader("statusCallbackUri")
	u, err := url.Parse(callback)
	if err != nil || u.Host != "issuer-waltid-dpg-adapter-waltid:8090" || !strings.HasPrefix(u.Path, "/callbacks/issuance/"+resp.Msg.GetOfferId()+"/") {
		t.Fatalf("callback = %q, offer id %q", callback, resp.Msg.GetOfferId())
	}
	return resp.Msg.GetOfferId(), u.Path
}

// post sends one recorded callback to the handler.
func postCallback(t *testing.T, h http.Handler, path, fixture string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, "doc", fixture)) //nolint:gosec // G304: a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw))))
	return rec.Code
}

func status(t *testing.T, svc *service.Service, id string) *backendv1.GetIssuanceStatusResponse {
	t.Helper()
	resp, err := svc.GetIssuanceStatus(context.Background(), connect.NewRequest(&backendv1.GetIssuanceStatusRequest{OfferId: id}))
	if err != nil {
		t.Fatalf("GetIssuanceStatus: %v", err)
	}
	return resp.Msg
}

func TestCallbackUpdatesIssuanceStatus(t *testing.T) {
	svc, f := newService(t, withCallbacks)
	h := svc.CallbackHandler()
	id, path := offer(t, svc, f)
	if got := status(t, svc, id); got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_PENDING {
		t.Fatalf("new offer = %v", got.GetState())
	}
	// A wrong token changes nothing.
	wrong := path[:strings.LastIndex(path, "/")+1] + "not-the-token"
	if code := postCallback(t, h, wrong, "callback-jwt-issue.json"); code != http.StatusNotFound {
		t.Fatalf("wrong token: %d", code)
	}
	if code := postCallback(t, h, "/callbacks/issuance/unknown/x", "callback-jwt-issue.json"); code != http.StatusNotFound {
		t.Fatalf("unknown offer: %d", code)
	}
	// An offer the wallet only read stays pending.
	if code := postCallback(t, h, path, "callback-resolved-offer.json"); code != http.StatusNoContent {
		t.Fatalf("resolved: %d", code)
	}
	if got := status(t, svc, id); got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_PENDING {
		t.Fatalf("after resolve = %v", got.GetState())
	}
	if code := postCallback(t, h, path, "callback-jwt-issue.json"); code != http.StatusNoContent {
		t.Fatalf("issued: %d", code)
	}
	got := status(t, svc, id)
	if got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_ISSUED || got.GetClaimedAt() == nil ||
		got.GetCredential().GetFormat() != commonv1.Format_FORMAT_JWT_VC_JSON || !strings.HasPrefix(string(got.GetCredential().GetPayload()), "eyJ") {
		t.Fatalf("issued = %+v", got)
	}
	// A later status keeps the issued state.
	if code := postCallback(t, h, path, "callback-status-expired.json"); code != http.StatusNoContent {
		t.Fatalf("expired after issue: %d", code)
	}
	if status(t, svc, id).GetState() != backendv1.GetIssuanceStatusResponse_STATE_ISSUED {
		t.Fatal("an expiry after the claim undid it")
	}

	failed, failedPath := offer(t, svc, f)
	if code := postCallback(t, h, failedPath, "callback-status-unsuccessful.json"); code != http.StatusNoContent {
		t.Fatalf("unsuccessful: %d", code)
	}
	if got := status(t, svc, failed); got.GetState() != backendv1.GetIssuanceStatusResponse_STATE_FAILED || !strings.Contains(got.GetError(), "proof of possession") {
		t.Fatalf("failed = %+v", got)
	}
	expired, expiredPath := offer(t, svc, f)
	if code := postCallback(t, h, expiredPath, "callback-status-expired.json"); code != http.StatusNoContent {
		t.Fatalf("expired: %d", code)
	}
	if status(t, svc, expired).GetState() != backendv1.GetIssuanceStatusResponse_STATE_EXPIRED {
		t.Fatal("the expiry is lost")
	}
	// A body that is not a callback is refused.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, expiredPath, strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("broken body: %d", rec.Code)
	}
	if _, err := svc.GetIssuanceStatus(context.Background(), connect.NewRequest(&backendv1.GetIssuanceStatusRequest{OfferId: "unknown"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown offer: %v", err)
	}
}

// TestCredentialCarriesStatusEntry reads the status entry of the claimed
// credential: the entry the adapter put in the offer comes back in the
// credential walt.id signed.
func TestCredentialCarriesStatusEntry(t *testing.T) {
	svc, f := newService(t, withCallbacks)
	id, path := offer(t, svc, f)
	var body map[string]any
	if err := f.RequestJSON("/openid4vc/jwt/issue", &body); err != nil {
		t.Fatal(err)
	}
	sent := mustAs[map[string]any](t, mustAs[map[string]any](t, body["credentialData"])["credentialStatus"])
	if code := postCallback(t, svc.CallbackHandler(), path, "callback-jwt-issue.json"); code != http.StatusNoContent {
		t.Fatalf("issued: %d", code)
	}
	parts := strings.Split(string(status(t, svc, id).GetCredential().GetPayload()), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"statusListIndex":"` + mustAs[string](t, sent["statusListIndex"]) + `"`, `"statusListCredential":"https://status.example.org/bitstring/1"`} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("the credential lacks %s: %s", want, payload)
		}
	}
}

func TestSessionCallbacksFeatureListed(t *testing.T) {
	for _, row := range []struct {
		r    roles
		want bool
	}{{withCallbacks, true}, {roles{issuer: true}, false}, {roles{wallet: true, callbacks: true}, false}} {
		svc, _ := newService(t, row.r)
		resp, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		listed := map[backendv1.Feature]bool{}
		for _, f := range resp.Msg.GetFeatures() {
			listed[f] = true
		}
		if listed[backendv1.Feature_FEATURE_ISSUANCE_STATUS] != row.want || listed[backendv1.Feature_FEATURE_SESSION_CALLBACKS] != row.want {
			t.Errorf("%+v: features %v", row.r, resp.Msg.GetFeatures())
		}
		// The community stack hosts no status list, so it revokes nothing.
		if listed[backendv1.Feature_FEATURE_REVOCATION] || listed[backendv1.Feature_FEATURE_SUSPENSION] {
			t.Errorf("%+v lists revocation", row.r)
		}
	}
	plain, _ := newService(t, roles{issuer: true})
	_, err := plain.GetIssuanceStatus(context.Background(), connect.NewRequest(&backendv1.GetIssuanceStatusRequest{OfferId: "x"}))
	wantCode(t, err, connect.CodeUnimplemented)
	rec := httptest.NewRecorder()
	plain.CallbackHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/callbacks/issuance/x/y", strings.NewReader("{}")))
	if rec.Code != http.StatusNotFound {
		t.Errorf("callbacks off: %d", rec.Code)
	}
}
