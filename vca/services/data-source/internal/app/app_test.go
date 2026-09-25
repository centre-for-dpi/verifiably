// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"

	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testDeps() Deps {
	return Deps{
		Getenv:   func(string) string { return "" },
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("no file") },
		Now:      func() time.Time { return time.Unix(1700000000, 0).UTC() },
		Log:      quiet(),
	}
}

// settings loads a configuration from the variables, on top of the
// defaults.
func settings(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	c, err := config.Load(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fixedTime is the clock of the sessions the tests sign.
var fixedTime = time.Unix(1700000000, 0).UTC()

// staff stands in for issuer-auth: it signs the sessions the tests send.
func staff(t *testing.T) *staffsessiontest.Issuer {
	t.Helper()
	return staffsessiontest.New(t, staffsession.IssuerAudience, fixedTime)
}

// TestBuildServesTheService proves the RPCs take a session of issuer-auth
// and nothing else: no bearer and the roles header of the old header
// mode both get unauthenticated.
func TestBuildServesTheService(t *testing.T) {
	issuer := staff(t)
	deps := testDeps()
	deps.SessionKeys = issuer.Keys()
	a, err := Build(settings(t, map[string]string{"VCA_DATASOURCE_ALLOW_HOSTS": "api.example.org"}), deps)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := datasourcev1connect.NewDataSourceServiceClient(srv.Client(), srv.URL)

	req := connect.NewRequest(&datasourcev1.CreateRequest{Source: &datasourcev1.Source{
		DisplayName: "Staff list",
		Kind:        &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: "staff.csv", HasHeader: true}},
		Access:      &datasourcev1.Source_Access{ViewFields: []string{authz.Viewer}},
	}})
	if _, serr := client.Create(context.Background(), req); connect.CodeOf(serr) != connect.CodeUnauthenticated {
		t.Fatalf("no session must be unauthenticated, got %v", serr)
	}
	req.Header().Set("X-VCA-Roles", authz.Admin)
	if _, serr := client.Create(context.Background(), req); connect.CodeOf(serr) != connect.CodeUnauthenticated {
		t.Fatalf("a roles header must not stand in for a session, got %v", serr)
	}
	req.Header().Set("Authorization", "Bearer "+issuer.Token(t, "kc|amina", authz.Admin))
	resp, err := client.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetSource().GetId() == "" {
		t.Fatal("the service must assign an id")
	}
}

func TestBuildHealthEndpointsAreNotRegisteredHere(t *testing.T) {
	a, err := Build(settings(t, nil), testDeps())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("serve.New adds the health endpoints, got %d", rec.Code)
	}
}

func TestBuildWithJWKSFile(t *testing.T) {
	issuer := staff(t)
	cfg := settings(t, map[string]string{"VCA_DATASOURCE_AUTH_JWKS_FILE": issuer.JWKSFile(t)})
	deps := testDeps()
	deps.ReadFile = os.ReadFile
	if _, err := Build(cfg, deps); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRejectsABadJWKSFile(t *testing.T) {
	cfg := settings(t, map[string]string{"VCA_DATASOURCE_AUTH_JWKS_FILE": "/missing"})
	if _, err := Build(cfg, testDeps()); err == nil {
		t.Fatal("a missing JWKS file must fail")
	}
}

func TestBuildRejectsABadStoreFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Build(settings(t, map[string]string{"VCA_DATASOURCE_STORE_FILE": dir}), testDeps()); err == nil {
		t.Fatal("a directory is not a store file")
	}
}

func TestBuildFillsNilDeps(t *testing.T) {
	if _, err := Build(settings(t, nil), Deps{Log: quiet()}); err != nil {
		t.Fatal(err)
	}
}
