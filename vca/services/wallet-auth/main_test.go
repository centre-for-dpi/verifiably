// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	if run([]string{"-bogus"}) != 2 {
		t.Fatal("bad flag")
	}
	t.Setenv("VCA_PUBLIC_URL", "")
	if run(nil) != 1 {
		t.Fatal("missing config accepted")
	}
	t.Setenv("VCA_PUBLIC_URL", "http://localhost:8081")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	t.Setenv("VCA_WALLET_AUTH_LISTEN", addr)
	if run([]string{"-healthcheck"}) != 1 {
		t.Fatal("healthcheck passed with nothing listening")
	}
	t.Setenv("VCA_SECRETS_SIGNING_KEY", filepath.Join(t.TempDir(), "missing.pem"))
	if run(nil) != 1 {
		t.Fatal("bad key accepted")
	}
	t.Setenv("VCA_SECRETS_SIGNING_KEY", "")
	// Occupy the port so the server cannot bind.
	busy, _ := net.Listen("tcp", addr)
	if run(nil) != 1 {
		t.Fatal("busy port accepted")
	}
	busy.Close()
	done := make(chan int, 1)
	go func() { done <- run(nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for run([]string{"-healthcheck"}) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
	}
}
