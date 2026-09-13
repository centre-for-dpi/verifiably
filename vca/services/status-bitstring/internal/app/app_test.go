// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
	"github.com/centre-for-dpi/vc-adapters/services/status-bitstring/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/status-bitstring/internal/securer"
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

// pemOf encodes one generated key as a PKCS #8 PEM file.
func pemOf(t *testing.T, alg jose.Algorithm) []byte {
	t.Helper()
	key, err := jose.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestBuildServesRPCAndPublicList(t *testing.T) {
	app, err := Build(context.Background(), load(t, nil), quiet())
	if err != nil {
		t.Fatal(err)
	}
	if !app.Service.Ready() || app.Manager == nil || app.Issuers == nil {
		t.Fatal("app is not ready")
	}
	srv := httptest.NewServer(app.Mux)
	defer srv.Close()
	client := statusv1connect.NewStatusServiceClient(srv.Client(), srv.URL)
	alloc, err := client.AllocateIndex(context.Background(), connect.NewRequest(&statusv1.AllocateIndexRequest{
		Purpose: statusv1.Purpose_PURPOSE_REVOCATION, Kind: statusv1.Kind_KIND_BITSTRING,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(alloc.Msg.GetUrl(), "http://localhost:8084/status/") {
		t.Fatalf("url = %s", alloc.Msg.GetUrl())
	}
	if _, err := client.SetStatus(context.Background(), connect.NewRequest(&statusv1.SetStatusRequest{
		ListId: alloc.Msg.GetListId(), Index: alloc.Msg.GetIndex(), Value: 1, Reason: "test",
	})); err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Get(srv.URL + "/status/" + alloc.Msg.GetListId())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != securer.MediaType {
		t.Fatalf("status %d type %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("ETag") == "" || !strings.Contains(resp.Header.Get("Cache-Control"), "max-age=300") {
		t.Fatalf("headers = %v", resp.Header)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	checkCredential(t, app, string(body), alloc.Msg.GetIndex())
	jwks, err := srv.Client().Get(srv.URL + "/.well-known/jwks.json")
	if err != nil || jwks.StatusCode != http.StatusOK {
		t.Fatalf("jwks: %v %v", err, jwks)
	}
	jwks.Body.Close()
}

// checkCredential verifies the signed credential with the service JWKS
// and reads the flipped index back from the bitstring.
func checkCredential(t *testing.T, app *App, token string, index int64) {
	t.Helper()
	set, err := jose.ParseJWKS(app.Manager.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	payload, header, err := jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if header.Typ != securer.Type {
		t.Fatalf("typ = %s", header.Typ)
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	purpose, list, err := bitstring.ParseCredential(doc)
	if err != nil {
		t.Fatal(err)
	}
	if purpose != bitstring.Revocation {
		t.Fatalf("purpose = %s", purpose)
	}
	on, err := list.Get(int(index))
	if err != nil || !on {
		t.Fatalf("bit at %d = %v %v", index, on, err)
	}
}

func TestBuildKeepsSignedBytesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := load(t, map[string]string{config.Prefix + "STATE_DIR": dir})
	first, err := Build(context.Background(), cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	alloc, err := first.Manager.Allocate(context.Background(), "", lists.Revocation, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, signed, err := first.Manager.Signed(context.Background(), alloc.ListID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(context.Background(), cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	_, again, err := second.Manager.Signed(context.Background(), alloc.ListID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := signed.Artifact(securer.MediaType)
	b, _ := again.Artifact(securer.MediaType)
	if string(a.Body) != string(b.Body) {
		t.Fatal("the service signed the list again after a restart")
	}
	if first.Issuers.Default().DID() != second.Issuers.Default().DID() {
		t.Fatal("the issuer changed after a restart")
	}
}

func TestBuildWithKeyFile(t *testing.T) {
	cfg := load(t, map[string]string{
		config.Prefix + "SIGNING_KEY_FILE": "/keys/status.pem",
		config.Prefix + "SIGNING_ALG":      "EdDSA",
	})
	data := pemOf(t, jose.EdDSA)
	deps := quiet()
	deps.ReadFile = func(string) ([]byte, error) { return data, nil }
	app, err := Build(context.Background(), cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(app.Issuers.Default().DID(), "did:jwk:") {
		t.Fatalf("did = %s", app.Issuers.Default().DID())
	}
}

func TestBuildErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := Build(ctx, config.Config{}, quiet()); err == nil {
		t.Fatal("empty config")
	}
	cfg := load(t, nil)
	cfg.SecuringMethod = securer.MethodDataIntegrity
	_, err := Build(ctx, cfg, quiet())
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("data integrity: %v", err)
	}
	if _, err := securer.New(cfg.SecuringMethod); !errors.Is(err, securer.ErrNotImplemented) {
		t.Fatalf("securer: %v", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := load(t, map[string]string{config.Prefix + "STATE_DIR": file})
	if _, err := Build(ctx, bad, quiet()); err == nil || !strings.Contains(err.Error(), "state directory") {
		t.Fatalf("state dir: %v", err)
	}
	withKey := load(t, map[string]string{config.Prefix + "SIGNING_KEY_FILE": "/nope.pem"})
	deps := quiet()
	deps.ReadFile = func(string) ([]byte, error) { return nil, errors.New("no such file") }
	if _, err := Build(ctx, withKey, deps); err == nil || !strings.Contains(err.Error(), "signing key file") {
		t.Fatalf("key file: %v", err)
	}
	deps.ReadFile = func(string) ([]byte, error) { return []byte("junk"), nil }
	if _, err := Build(ctx, withKey, deps); err == nil {
		t.Fatal("bad key file")
	}
}

func TestBuildFillsDefaultDeps(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	cfg := load(t, nil)
	if _, err := Build(context.Background(), cfg, Deps{}); err != nil {
		t.Fatal(err)
	}
}
