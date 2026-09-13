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
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
	"github.com/centre-for-dpi/vc-adapters/services/status-token/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/status-token/internal/securer"
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

func get(t *testing.T, srv *httptest.Server, path, accept string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestBuildServesJWTAndCWTFromOneBitArray(t *testing.T) {
	cfg := load(t, map[string]string{config.Prefix + "DEFAULT_BITS": "2"})
	app, err := Build(context.Background(), cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if !app.Service.Ready() {
		t.Fatal("app is not ready")
	}
	srv := httptest.NewServer(app.Mux)
	defer srv.Close()
	client := statusv1connect.NewStatusServiceClient(srv.Client(), srv.URL)
	alloc, err := client.AllocateIndex(context.Background(), connect.NewRequest(&statusv1.AllocateIndexRequest{
		Purpose: statusv1.Purpose_PURPOSE_SUSPENSION, Kind: statusv1.Kind_KIND_TOKEN,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SetStatus(context.Background(), connect.NewRequest(&statusv1.SetStatusRequest{
		ListId: alloc.Msg.GetListId(), Index: alloc.Msg.GetIndex(), Value: 2, Reason: "test",
	})); err != nil {
		t.Fatal(err)
	}
	path := "/status/" + alloc.Msg.GetListId()
	index := int(alloc.Msg.GetIndex())

	resp, body := get(t, srv, path, "")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != securer.MediaTypeJWT {
		t.Fatalf("default: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "max-age=300") || resp.Header.Get("ETag") == "" {
		t.Fatalf("headers = %v", resp.Header)
	}
	checkJWT(t, app, string(body), index)

	cwtResp, cwtBody := get(t, srv, path, securer.MediaTypeCWT)
	if cwtResp.StatusCode != http.StatusOK || cwtResp.Header.Get("Content-Type") != securer.MediaTypeCWT {
		t.Fatalf("cwt: %d %s", cwtResp.StatusCode, cwtResp.Header.Get("Content-Type"))
	}
	checkCWT(t, app, cwtBody, index)

	notAcceptable, _ := get(t, srv, path, "application/pdf")
	if notAcceptable.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("accept: %d", notAcceptable.StatusCode)
	}
	cached, _ := get(t, srv, path, "")
	if cached.Header.Get("ETag") != resp.Header.Get("ETag") {
		t.Fatal("the ETag changed without a write")
	}
}

// checkJWT verifies the Status List JWT and reads the index back.
func checkJWT(t *testing.T, app *App, jwt string, index int) {
	t.Helper()
	set, err := jose.ParseJWKS(app.Manager.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	payload, header, err := jose.VerifyWithJWKS(jwt, set, jose.SigningAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if header.Typ != token.TypeJWT {
		t.Fatalf("typ = %s", header.Typ)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	parsed, list, err := token.ParseJWTClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Issuer != app.Issuers.Default().DID() {
		t.Fatalf("iss = %s", parsed.Issuer)
	}
	if list.Bits() != 2 {
		t.Fatalf("bits = %d", list.Bits())
	}
	if v, err := list.Get(index); err != nil || v != 2 {
		t.Fatalf("value at %d = %d %v", index, v, err)
	}
}

// checkCWT verifies the Status List CWT with the active public key.
func checkCWT(t *testing.T, app *App, msg []byte, index int) {
	t.Helper()
	key := app.Issuers.Default().Active()
	payload, err := token.VerifyCWT(msg, token.KeyVerifier(key.Public(app.Issuers.Default().Kid(key)).Key))
	if err != nil {
		t.Fatal(err)
	}
	_, list, err := token.ParseCWTClaims(payload)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := list.Get(index); err != nil || v != 2 {
		t.Fatalf("value at %d = %d %v", index, v, err)
	}
}

func TestBuildKeepsSignedBytesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := load(t, map[string]string{config.Prefix + "STATE_DIR": dir})
	first, err := Build(context.Background(), cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	alloc, err := first.Manager.Allocate(context.Background(), "", lists.Revocation, 0)
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
	for _, mediaType := range []string{securer.MediaTypeJWT, securer.MediaTypeCWT} {
		a, _ := signed.Artifact(mediaType)
		b, _ := again.Artifact(mediaType)
		if string(a.Body) != string(b.Body) {
			t.Fatalf("%s: the service signed the list again after a restart", mediaType)
		}
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
	if _, err := Build(context.Background(), load(t, nil), Deps{}); err != nil {
		t.Fatal(err)
	}
}
