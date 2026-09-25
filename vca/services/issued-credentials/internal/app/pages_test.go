// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := load(t, nil)
	cfg.ThemeFile = path
	_, err := app.Build(cfg, app.Deps{Log: quiet()})
	uikittest.AssertBadThemeError(t, err, path)
}

// cookieGet answers one GET, with the session cookie when token is set.
func cookieGet(a *app.App, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	return rec
}

// TestIssuedPagesNeedSession proves the pages sit behind the guard of
// issuer-auth, while the chain head, its key set, and the assets stay
// public for an auditor and a browser.
func TestIssuedPagesNeedSession(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, time.Now())
	a := build(t, map[string]string{"VCA_ISSUED_LOGIN_URL": "https://issuer.example/auth/"}, app.Deps{SessionKeys: issuer.Keys(), Now: time.Now})
	if _, err := a.Service.AppendRecord(record.Record{ID: "rec-1", SchemaID: "farmer", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/issued/", "/issued/rec-1", "/issued/export.csv"} {
		rec := cookieGet(a, path, "")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "https://issuer.example/auth/?return_to=") {
			t.Errorf("%s without a session: status %d location %q", path, rec.Code, rec.Header().Get("Location"))
		}
		if rec := cookieGet(a, path, issuer.Token(t, "kc|wanjiru", "issuer-operator")); rec.Code != http.StatusOK {
			t.Errorf("%s with a session: status %d %s", path, rec.Code, rec.Body.String())
		}
	}
	for _, path := range []string{httpapi.ChainHeadPath, httpapi.JWKSPath, ui.Prefix + "vca.css"} {
		if rec := cookieGet(a, path, ""); rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, rec.Code)
		}
	}
}

// fakeAdapter answers as the capability and issuer services of the
// adapter of the pair.
type fakeAdapter struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
	revoked chan *backendv1.RevokeRequest
}

func (f *fakeAdapter) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{Features: []backendv1.Feature{backendv1.Feature_FEATURE_REVOCATION}}), nil
}

func (f *fakeAdapter) Revoke(_ context.Context, req *connect.Request[backendv1.RevokeRequest]) (*connect.Response[backendv1.RevokeResponse], error) {
	f.revoked <- req.Msg
	return connect.NewResponse(&backendv1.RevokeResponse{}), nil
}

// TestBuildWiresTheStackFromTheAdapterURL sends the revoke of a ledger
// record to the adapter of the pair when it lists FEATURE_REVOCATION.
func TestBuildWiresTheStackFromTheAdapterURL(t *testing.T) {
	f := &fakeAdapter{revoked: make(chan *backendv1.RevokeRequest, 1)}
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(f))
	mux.Handle(backendv1connect.NewIssuerBackendServiceHandler(f))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	a := build(t, map[string]string{"VCA_ISSUED_ADAPTER_URL": srv.URL}, app.Deps{})
	if _, err := a.Service.AppendRecord(record.Record{ID: "rec-1", SchemaID: "farmer", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: clock,
		DPGCredentialID: "urn:uuid:4", Binding: record.Binding{Kind: record.KindBitstring, ListID: "list-1", Index: 4}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Service.Revoke(context.Background(), connect.NewRequest(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_REVOKED, Reason: "Lost"})); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-f.revoked:
		if got.GetStatus().GetIndex() != 4 || got.GetReason() != "Lost" || got.GetCredentialId() != "urn:uuid:4" {
			t.Fatalf("revoke = %v", got)
		}
	default:
		t.Fatal("the adapter took no revoke")
	}
}
