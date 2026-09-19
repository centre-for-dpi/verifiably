// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/config"
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

func TestBuildServesTheService(t *testing.T) {
	a, err := Build(config.Config{PageSizeMax: 10, AllowHosts: []string{"api.example.org"}}, testDeps())
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
	req.Header().Set(authz.HeaderRoles, authz.Admin)
	resp, err := client.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetSource().GetId() == "" {
		t.Fatal("the service must assign an id")
	}
}

func TestBuildHealthEndpointsAreNotRegisteredHere(t *testing.T) {
	a, err := Build(config.Config{PageSizeMax: 10}, testDeps())
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
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.PublicJWK(key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jose.JWKS{Keys: []jose.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	deps := testDeps()
	deps.ReadFile = func(string) ([]byte, error) { return set, nil }
	if _, err := Build(config.Config{PageSizeMax: 10, AuthJWKSFile: "/run/jwks.json"}, deps); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRejectsABadJWKSFile(t *testing.T) {
	deps := testDeps()
	if _, err := Build(config.Config{PageSizeMax: 10, AuthJWKSFile: "/missing"}, deps); err == nil {
		t.Fatal("a missing JWKS file must fail")
	}
	deps.ReadFile = func(string) ([]byte, error) { return []byte("{"), nil }
	if _, err := Build(config.Config{PageSizeMax: 10, AuthJWKSFile: "/bad"}, deps); err == nil {
		t.Fatal("a bad JWKS file must fail")
	}
}

func TestBuildRejectsABadStoreFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Build(config.Config{PageSizeMax: 10, StoreFile: dir}, testDeps()); err == nil {
		t.Fatal("a directory is not a store file")
	}
}

func TestBuildFillsNilDeps(t *testing.T) {
	if _, err := Build(config.Config{PageSizeMax: 10}, Deps{Log: quiet()}); err != nil {
		t.Fatal(err)
	}
}
