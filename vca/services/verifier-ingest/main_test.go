// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// env returns a getenv function over a map.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// freePort returns an address no other process listens on.
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

func TestRunFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, env(nil), &out, &errOut); code != 2 {
		t.Errorf("an unknown flag answers %d", code)
	}
	out.Reset()
	if code := run(context.Background(), []string{"-version"}, env(nil), &out, &errOut); code != 0 {
		t.Errorf("the version flag answers %d", code)
	}
	if strings.TrimSpace(out.String()) != version {
		t.Errorf("version = %q", out.String())
	}
}

func TestRunConfigError(t *testing.T) {
	var out, errOut bytes.Buffer
	bad := env(map[string]string{"VCA_INGEST_MAX_INPUT_BYTES": "0"})
	if code := run(context.Background(), nil, bad, &out, &errOut); code != 1 {
		t.Errorf("a bad setting answers %d", code)
	}
	if !strings.Contains(errOut.String(), "MAX_INPUT_BYTES") {
		t.Errorf("the message names the setting, got %q", errOut.String())
	}
}

func TestRunBuildError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state")
	if err := writeEmpty(file); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	broken := env(map[string]string{"VCA_INGEST_STATE_DIR": file})
	if code := run(context.Background(), nil, broken, &out, &errOut); code != 1 {
		t.Errorf("a state directory that is a file answers %d", code)
	}
}

func TestRunServesAndHealthchecks(t *testing.T) {
	addr := freePort(t)
	settings := env(map[string]string{"VCA_INGEST_LISTEN": addr})
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-healthcheck"}, settings, &out, &errOut); code != 1 {
		t.Errorf("a probe without a server answers %d", code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, settings, &out, &errOut) }()
	waitReady(t, addr)
	if code := run(context.Background(), []string{"-healthcheck"}, settings, &out, &errOut); code != 0 {
		t.Errorf("the probe answers %d: %s", code, errOut.String())
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("the server exits with %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "listening") {
		t.Error("the server logs that it listens")
	}
	listenError := env(map[string]string{"VCA_INGEST_LISTEN": "300.0.0.1:x"})
	if code := run(context.Background(), nil, listenError, &out, &errOut); code != 1 {
		t.Errorf("a bad address answers %d", code)
	}
}

// writeEmpty makes an empty file at path.
func writeEmpty(path string) error {
	return os.WriteFile(path, nil, 0o600)
}

// waitReady waits until the server answers /readyz.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/readyz", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			if cerr := resp.Body.Close(); cerr != nil {
				t.Errorf("the close failed: %v", cerr)
			}
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the server did not start")
		}
		time.Sleep(20 * time.Millisecond)
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
