// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func load(t *testing.T, env map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func quiet() Deps {
	return Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return t0 }}
}

func TestBuildWithGeneratedKey(t *testing.T) {
	cfg := load(t, map[string]string{"VCA_TRUST_RESOLVE_DIDS": "false"})
	app, err := Build(cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Mux)
	defer srv.Close()
	for _, path := range []string{"/trust-list/etsi.json", "/trust-list/etsi.jws", "/.well-known/jwks.json", "/.well-known/dedi.index.json", "/dedi/dedi.issuers.json"} {
		resp, getErr := srv.Client().Get(srv.URL + path)
		if getErr != nil {
			t.Errorf("%s: %v", path, getErr)
			continue
		}
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", path, resp.StatusCode)
		}
	}
	client := trustv1connect.NewTrustServiceClient(srv.Client(), srv.URL)
	e := &trustv1.TrustEntry{Identifier: &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:a.example"}}, Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_ACTIVE}
	if _, serr := client.UpsertEntry(context.Background(), connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: e})); serr != nil {
		t.Fatal(serr)
	}
	r, err := client.TrustLookup(context.Background(), connect.NewRequest(&trustv1.TrustLookupRequest{Identifier: e.Identifier, Role: commonv1.Role_ROLE_ISSUER}))
	if err != nil || r.Msg.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Fatal("lookup", err)
	}
}

func TestBuildWithKeyFileAndStoreFile(t *testing.T) {
	dir := t.TempDir()
	k, verr := keys.Generate(jose.EdDSA, t0)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	pemData, verr := keys.EncodePEM([]keys.Key{k})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	cfg := load(t, map[string]string{
		"VCA_TRUST_SIGNING_KEY_FILE": filepath.Join(dir, "key.pem"),
		"VCA_TRUST_STORE_FILE":       filepath.Join(dir, "trust.json"),
		"VCA_TRUST_METHODS":          "dedi",
	})
	deps := quiet()
	deps.ReadFile = func(string) ([]byte, error) { return pemData, nil }
	deps.Fetch = func(_ context.Context, url string) ([]byte, error) {
		return []byte(`{"id":"did:web:a.example"}`), nil
	}
	app, err := Build(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	if app.Ring.Active().ID != k.ID || len(app.Service.Snapshot().Methods()) != 1 {
		t.Fatal("ring or methods")
	}
	e := &trustv1.TrustEntry{Identifier: &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:a.example"}}, Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_ACTIVE}
	if _, serr := app.Service.UpsertEntry(context.Background(), connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: e})); serr != nil {
		t.Fatal(serr)
	}
	again, err := Build(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := again.Service.Snapshot().Publication("dedi"); p.EntryCount != 1 {
		t.Fatal("store file persists across builds")
	}
}

func TestBuildErrors(t *testing.T) {
	deps := quiet()
	deps.ReadFile = func(string) ([]byte, error) { return nil, errors.New("no file") }
	if _, err := Build(load(t, map[string]string{"VCA_TRUST_SIGNING_KEY_FILE": "/k.pem"}), deps); err == nil {
		t.Fatal("read error")
	}
	deps.ReadFile = func(string) ([]byte, error) { return []byte("not pem"), nil }
	if _, err := Build(load(t, map[string]string{"VCA_TRUST_SIGNING_KEY_FILE": "/k.pem"}), deps); err == nil {
		t.Fatal("parse error")
	}
	bad := load(t, nil)
	bad.SigningAlg = "HS256"
	if _, err := Build(bad, quiet()); err == nil {
		t.Fatal("generate error")
	}
	dir := t.TempDir()
	if _, err := Build(load(t, map[string]string{"VCA_TRUST_STORE_FILE": dir}), quiet()); err == nil {
		t.Fatal("store error")
	}
	zero := load(t, nil)
	zero.ListTTL = 0
	zero.Methods = nil
	if _, err := Build(zero, quiet()); err == nil {
		t.Fatal("service error")
	}
	if _, err := Build(load(t, nil), Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal("default deps", err)
	}
}

func TestHTTPFetcher(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, writeStringErr := io.WriteString(w, strings.Repeat("x", MaxDocumentSize+10)); writeStringErr != nil {
			t.Fatalf("unexpected error: %v", writeStringErr)
		}
	}))
	defer srv.Close()
	fetch := HTTPFetcher(srv.Client())
	body, err := fetch(context.Background(), srv.URL+"/.well-known/did.json")
	if err != nil || len(body) != MaxDocumentSize {
		t.Fatalf("fetch %v %d", err, len(body))
	}
	if _, err := fetch(context.Background(), srv.URL+"/missing"); err == nil {
		t.Fatal("404")
	}
	if _, err := fetch(context.Background(), "http://plain.example/did.json"); err == nil {
		t.Fatal("http refused")
	}
	if _, err := fetch(context.Background(), "https://bad host/"); err == nil {
		t.Fatal("bad url")
	}
	if _, err := HTTPFetcher(&http.Client{Timeout: time.Millisecond})(context.Background(), "https://127.0.0.1:1/"); err == nil {
		t.Fatal("connection error")
	}
}
