// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/limits"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/server"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func baseConfig(t *testing.T) config.Config {
	t.Helper()
	c, err := config.FromEnv(func(k string) string {
		switch k {
		case "VCA_PUBLIC_URL":
			return "http://localhost:8083"
		case "VCA_WALLET_AUTH_STATE_DIR":
			return filepath.Join(t.TempDir(), "state")
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuild(t *testing.T) {
	cfg := baseConfig(t)
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Providers().List()) != 0 {
		t.Fatal("no seed expected")
	}
	// A seed provider from the environment lands under id "default".
	cfg.Seed = config.SeedProvider{DiscoveryURL: "https://idp/.well-known/openid-configuration", ClientID: "c", ClientSecretEnv: "S"}
	svc, err = server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Providers().Get("default")
	if err != nil || p.ClientSecret.Name != "S" || !p.Enabled {
		t.Fatalf("seed: %+v %v", p, err)
	}
	// A second build keeps the stored record and does not overwrite it.
	_, _ = svc.Providers().Put(oidcflow.Provider{ID: "default", DisplayName: "Kept", DiscoveryURL: p.DiscoveryURL, ClientID: "c", Enabled: true})
	svc, _ = server.Build(cfg, quiet)
	if p, _ := svc.Providers().Get("default"); p.DisplayName != "Kept" {
		t.Fatal("seed overwrote the stored provider")
	}
	// A signing key file is used, and its kid is stable.
	key, _ := oidcflow.GenerateKey()
	pem, _ := oidcflow.EncodeKeyPEM(key)
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "key.pem")
	_ = os.WriteFile(cfg.SigningKeyPath, pem, 0o600)
	cfg.SessionKey = "0123456789abcdef0123456789abcdef"
	cfg.AdminToken = "t"
	a, _ := server.Build(cfg, quiet)
	b, _ := server.Build(cfg, quiet)
	if a.Signer().KeyID() != b.Signer().KeyID() {
		t.Fatal("kid differs between builds")
	}
	// Failures.
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("missing key accepted")
	}
	_ = os.WriteFile(cfg.SigningKeyPath, []byte("junk"), 0o600)
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("bad key accepted")
	}
	cfg.SigningKeyPath = ""
	cfg.SessionKey = "short"
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("short session key accepted")
	}
	cfg.SessionKey = ""
	cfg.StateDir = t.TempDir()
	cfg.Seed.DiscoveryURL = "nope"
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("bad seed accepted")
	}
	cfg.Seed = config.SeedProvider{}
	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, nil, 0o600)
	cfg.StateDir = filepath.Join(file, "x")
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("bad state dir accepted")
	}
	// Redis is selected but this build has no client.
	cfg.StateDir = t.TempDir()
	cfg.RedisURL = "redis://cache:6379"
	if _, err := server.Build(cfg, quiet); !errors.Is(err, limits.ErrNotConfigured) {
		t.Fatalf("redis: %v", err)
	}
	cfg.RedisURL = ""
	// A holder backend URL selects the Connect registrar.
	cfg.HolderBackendURL = "http://adapter:8090"
	cfg.Salt = []byte("0123456789abcdef")
	cfg.GrantKey = []byte("0123456789abcdef0123456789abcdef")
	if _, err := server.Build(cfg, quiet); err != nil {
		t.Fatal(err)
	}
	cfg.HolderBackendURL = ""
	for _, doc := range []string{"providers", "wallets", "grants"} {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, doc+".json"), []byte("{bad"), 0o600)
		cfg.StateDir = dir
		if _, err := server.Build(cfg, quiet); err == nil {
			t.Fatalf("corrupt %s accepted", doc)
		}
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestRunAndHealthcheck(t *testing.T) {
	cfg := baseConfig(t)
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	if err := server.Healthcheck(addr); err == nil {
		t.Fatal("healthcheck passed with nothing listening")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, addr, server.Handler(svc), quiet) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := server.Healthcheck(addr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, port, _ := net.SplitHostPort(addr)
	if err := server.Healthcheck(":" + port); err != nil {
		t.Fatalf("empty host: %v", err)
	}
	res, err := http.Get("http://" + addr + "/readyz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("readyz: %v", err)
	}
	res.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// A busy port makes Run fail.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	if err := server.Run(context.Background(), ln.Addr().String(), server.Handler(svc), quiet); err == nil {
		t.Fatal("busy port accepted")
	}
	if err := server.Healthcheck("bad"); err == nil {
		t.Fatal("bad addr accepted")
	}
	// A handler that answers 500 fails the healthcheck.
	bad := http.NewServeMux()
	bad.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	addr2 := freePort(t)
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { _ = server.Run(ctx2, addr2, bad, quiet) }()
	time.Sleep(50 * time.Millisecond)
	if err := server.Healthcheck(addr2); err == nil {
		t.Fatal("500 passed")
	}
	cancel2()
}
