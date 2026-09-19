// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	return addr
}

// jwksFile writes a key set the session middleware can read.
func jwksFile(t *testing.T) string {
	t.Helper()
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key.Public(), "k1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JWKS{Keys: []jose.JWK{pub}})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestRunPrintsVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, env(nil), &out, &errOut); code != 0 {
		t.Fatalf("version: %d", code)
	}
	if strings.TrimSpace(out.String()) != version {
		t.Fatalf("out = %q", out.String())
	}
}

func TestRunFlagsAndConfigErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, env(nil), &out, &errOut); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
	bad := env(map[string]string{"VCA_WALLET_PORTAL_PAGE_SIZE_MAX": "0"})
	if code := run(context.Background(), nil, bad, &out, &errOut); code != 1 ||
		!strings.Contains(errOut.String(), "PAGE_SIZE_MAX") {
		t.Fatalf("bad config: %d %s", code, errOut.String())
	}
	errOut.Reset()
	noKeys := env(map[string]string{"VCA_WALLET_PORTAL_LISTEN": ":0"})
	if code := run(context.Background(), nil, noKeys, &out, &errOut); code != 1 ||
		!strings.Contains(errOut.String(), "AUTH_JWKS") {
		t.Fatalf("no key set: %d %s", code, errOut.String())
	}
}

func TestRunServesAndHealthchecks(t *testing.T) {
	addr := freePort(t)
	e := env(map[string]string{
		"VCA_WALLET_PORTAL_LISTEN":         addr,
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": jwksFile(t),
	})
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-healthcheck"}, e, &out, &errOut); code != 1 {
		t.Fatalf("healthcheck with no server: %d", code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, e, &out, &errOut) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			if cerr := resp.Body.Close(); cerr != nil {
				t.Errorf("the close failed: %v", cerr)
			}
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := run(context.Background(), []string{"-healthcheck"}, e, &out, &errOut); code != 0 {
		t.Fatalf("healthcheck: %d %s", code, errOut.String())
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("server exit: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "listening") {
		t.Fatal("want a listening log line")
	}
	badAddr := env(map[string]string{
		"VCA_WALLET_PORTAL_LISTEN":         "300.0.0.1:x",
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": jwksFile(t),
	})
	if code := run(ctx, nil, badAddr, &out, &errOut); code != 1 {
		t.Fatalf("listen error: %d", code)
	}
}

// failWriter fails every write. It drives the printLine error path.
type failWriter struct{}

// Write always reports an error.
func (failWriter) Write([]byte) (int, error) {
	return 0, errors.New("the write failed")
}

func TestPrintLineReportsTheWriteStatus(t *testing.T) {
	if got := printLine(io.Discard, "ok"); got != 0 {
		t.Fatalf("want status 0, got %d", got)
	}
	if got := printLine(failWriter{}, "ok"); got != 1 {
		t.Fatalf("want status 1, got %d", got)
	}
}
