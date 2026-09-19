// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
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
	ln, verr := net.Listen("tcp", "127.0.0.1:0")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	addr := ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	t.Setenv("VCA_ISSUER_AUTH_LISTEN", addr)
	if run([]string{"-healthcheck"}) != 1 {
		t.Fatal("healthcheck passed with nothing listening")
	}
	t.Setenv("VCA_SECRETS_SIGNING_KEY", filepath.Join(t.TempDir(), "missing.pem"))
	if run(nil) != 1 {
		t.Fatal("bad key accepted")
	}
	t.Setenv("VCA_SECRETS_SIGNING_KEY", "")
	// Occupy the port so the server cannot bind.
	busy, verr := net.Listen("tcp", addr)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if run(nil) != 1 {
		t.Fatal("busy port accepted")
	}
	if cerr := busy.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	done := make(chan int, 1)
	go func() { done <- run(nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for run([]string{"-healthcheck"}) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if cerr := syscall.Kill(os.Getpid(), syscall.SIGTERM); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
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
