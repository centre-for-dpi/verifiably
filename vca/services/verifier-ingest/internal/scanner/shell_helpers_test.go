// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// shellMux wires the scanner in the verifier frame of the first pair,
// with the second pair live. The own adapter lists features. change
// adjusts the options before the page is built.
func shellMux(t *testing.T, change func(*scanner.Options), features ...backendv1.Feature) *http.ServeMux {
	t.Helper()
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example",
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	pair := func(dpg configv1.Dpg) topology.Peer {
		name := topology.PairName(commonv1.Role_ROLE_VERIFIER, dpg)
		return topology.Peer{Pair: name, Role: commonv1.Role_ROLE_VERIFIER, Dpg: dpg, PublicURL: "https://" + name + ".labs.example",
			Services: map[string]string{"verifier-auth": "http://" + name + "-auth:8081", topology.AdapterService(dpg): "http://" + name + "-adapter:8080"}}
	}
	first, second := pair(configv1.Dpg_DPG_WALTID), pair(configv1.Dpg_DPG_INJI)
	snap := topology.Snapshot{Peers: []topology.Status{
		{Peer: first, State: topology.Live, Capabilities: &backendv1.GetCapabilitiesResponse{
			DpgInfo: &backendv1.DpgInfo{DisplayName: "First stack"}, Features: features,
		}},
		{Peer: second, State: topology.Live, Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: "Second stack"}}},
	}}
	opts := scanner.Options{Client: svc, SignOut: http.NotFoundHandler(), Shell: staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: []topology.Peer{first, second},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  first.Auth() + staffshell.JWKSPath, SignOut: "/scan/signout",
	})}
	if change != nil {
		change(&opts)
	}
	page, err := scanner.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if page.SignOutPath() != "/scan/signout" {
		t.Fatalf("sign out path %q", page.SignOutPath())
	}
	mux := http.NewServeMux()
	page.Register(mux)
	return mux
}

// formPost returns a form POST request.
func formPost(path string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// staffDo answers one request as a signed in verifier operator.
func staffDo(t *testing.T, mux *http.ServeMux, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	r = r.WithContext(staffsession.With(r.Context(), staffsession.Session{
		Subject: "kc|otieno", Name: "Akinyi Otieno", CSRF: "csrf-1", Roles: []string{"verifier-operator"},
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}
