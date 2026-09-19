// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// quiet drops the log messages of the tests.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// settings returns a configuration for the tests.
func settings(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	base := map[string]string{"VCA_INGEST_STATE_DIR": filepath.Join(t.TempDir(), "state")}
	for k, v := range values {
		base[k] = v
	}
	cfg, err := config.Load(func(name string) string { return base[name] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// keyPEM writes one ES256 key as a PKCS 8 PEM file.
func keyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestBuildAndServe(t *testing.T) {
	a, err := app.Build(settings(t, nil), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Service.Ready() {
		t.Fatal("the wiring returns a ready service")
	}
	s := httptest.NewServer(a.Mux)
	defer s.Close()
	for _, path := range []string{"/scan/", "/scan/static/scanner.js", "/static/vca.css"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s answered %d", path, resp.StatusCode)
		}
	}
}

func TestBuildWithSigningKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, keyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": path}), app.Deps{Log: quiet()}); err != nil {
		t.Fatalf("a PEM key file must load: %v", err)
	}
}

func TestBuildKeyErrors(t *testing.T) {
	cases := map[string]func(string) []byte{
		"missing file": nil,
		"no key block": func(string) []byte { return []byte("not a pem file") },
		"broken key":   func(string) []byte { return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}) },
		"other block": func(string) []byte {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if write != nil {
				if err := os.WriteFile(path, write(path), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": path}), app.Deps{Log: quiet()})
			if err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestBuildRejectsBadStateDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Build(settings(t, map[string]string{"VCA_INGEST_STATE_DIR": file}), app.Deps{Log: quiet()}); err == nil {
		t.Error("a state directory that is a file wants an error")
	}
}

func TestBuildWithDiscoveryURLAndDefaults(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{
		"VCA_INGEST_DISCOVERY_URL": "http://127.0.0.1:1",
		"VCA_INGEST_XML_ENCODING":  "base64",
		"VCA_INGEST_XML_PATH":      "root.vc",
	}), app.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Config.XMLEncoding != "base64" {
		t.Errorf("config = %+v", a.Config)
	}
}

func TestPrune(t *testing.T) {
	a, err := app.Build(settings(t, nil), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	a.PruneInterval = 5 * time.Millisecond
	if serr := a.Store.Put(context.Background(), txn.Transaction{ID: "old", CreatedAt: time.Unix(0, 0).UTC()}); serr != nil {
		t.Fatal(serr)
	}
	if serr := a.Store.Put(context.Background(), txn.Transaction{ID: "new", CreatedAt: time.Now()}); serr != nil {
		t.Fatal(serr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	a.Prune(ctx, quiet())
	list, err := a.Store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "new" {
		t.Errorf("the job removed the old transaction only, got %+v", list)
	}
}

func TestPruneOff(t *testing.T) {
	a, err := app.Build(settings(t, nil), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	a.Config.TransactionTTL = 0
	// The job returns at once, so the test does not block.
	a.Prune(context.Background(), quiet())
}

func TestPruneLogsFailure(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{"VCA_INGEST_STATE_DIR": ""}), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	a.PruneInterval = 5 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	a.Prune(ctx, quiet())
}

func TestParsePEMRejectsKeyThatCannotSign(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": path}), app.Deps{Log: quiet()}); err == nil {
		t.Error("a key that cannot sign wants an error")
	}
}

func TestBuildReadFileInjection(t *testing.T) {
	_, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": "/keys/ingest.pem"}), app.Deps{
		Log:      quiet(),
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("no such file") },
	})
	if err == nil {
		t.Error("a read error wants an error")
	}
}
