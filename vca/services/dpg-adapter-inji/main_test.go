// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// env returns a lookup function for the values.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// freePort returns an address no process listens on.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	return addr
}

func TestRunReportsABadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, env(nil), &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRunReportsABadConfiguration(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), nil, env(nil), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "CERTIFY_URL") {
		t.Fatalf("exit code = %d, error = %q", code, errOut.String())
	}
}

func TestRunReportsAFailedWiring(t *testing.T) {
	dir := t.TempDir()
	blocking := filepath.Join(dir, "file")
	if err := writeEmptyFile(blocking); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errOut bytes.Buffer
	code := run(context.Background(), nil, env(map[string]string{
		"VCA_INJI_CERTIFY_URL": "http://issuer.example",
		"VCA_INJI_STORE_FILE":  filepath.Join(blocking, "state"),
	}), &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRunServesAndAnswersTheHealthcheck(t *testing.T) {
	addr := freePort(t)
	e := env(map[string]string{
		"VCA_INJI_LISTEN":      addr,
		"VCA_INJI_CERTIFY_URL": "http://issuer.example",
	})
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-healthcheck"}, e, &out, &errOut); code != 1 {
		t.Fatalf("the healthcheck passed without a server: %d", code)
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
			t.Fatal("the server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := run(context.Background(), []string{"-healthcheck"}, e, &out, &errOut); code != 0 {
		t.Fatalf("healthcheck exit code = %d, error = %q", code, errOut.String())
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("server exit code = %d, error = %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "listening") {
		t.Fatal("the start log is missing")
	}
}

func TestRunReportsABadListenAddress(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), nil, env(map[string]string{
		"VCA_INJI_LISTEN":      "300.0.0.1:notaport",
		"VCA_INJI_CERTIFY_URL": "http://issuer.example",
	}), &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
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
