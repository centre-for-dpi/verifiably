// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
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

func TestRunFlagsAndConfigErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, env(nil), &out, &errOut); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
	bad := env(map[string]string{"VCA_ISSUED_PAGE_SIZE_MAX": "x"})
	if code := run(context.Background(), nil, bad, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "PAGE_SIZE_MAX") {
		t.Fatalf("bad config: %d %s", code, errOut.String())
	}
	errOut.Reset()
	missing := env(map[string]string{"VCA_ISSUED_HEAD_KEY_FILE": "/nope.pem"})
	if code := run(context.Background(), nil, missing, &out, &errOut); code != 1 {
		t.Fatalf("build error: %d", code)
	}
}

func TestRunServesAndHealthchecks(t *testing.T) {
	addr := freePort(t)
	e := env(map[string]string{
		"VCA_ISSUED_LISTEN":         addr,
		"VCA_ISSUED_PRUNE_INTERVAL": "1ms",
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
		t.Fatal("log")
	}
	listenError := env(map[string]string{"VCA_ISSUED_LISTEN": "300.0.0.1:x"})
	if code := run(ctx, nil, listenError, &out, &errOut); code != 1 {
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
