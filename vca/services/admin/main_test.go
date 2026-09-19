// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// env returns a lookup over a map.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// freePort returns an address that no server uses.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

func TestRunReportsABadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, env(nil), &out, &errOut); code != 2 {
		t.Fatalf("code = %d", code)
	}
}

func TestRunReportsABadConfiguration(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), nil, env(nil), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "PUBLIC_URL") {
		t.Fatalf("code = %d output = %q", code, errOut.String())
	}
}

func TestRunReportsABuildFault(t *testing.T) {
	var out, errOut bytes.Buffer
	e := env(map[string]string{
		"VCA_ADMIN_PUBLIC_URL":  "http://127.0.0.1:8093",
		"VCA_ADMIN_SIGNING_KEY": "/nowhere/absent.pem",
	})
	if code := run(context.Background(), nil, e, &out, &errOut); code != 1 {
		t.Fatalf("code = %d output = %q", code, errOut.String())
	}
}

func TestRunServesAndAnswersTheHealthcheck(t *testing.T) {
	addr := freePort(t)
	e := env(map[string]string{
		"VCA_ADMIN_LISTEN":     addr,
		"VCA_ADMIN_PUBLIC_URL": "http://" + addr,
	})
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-healthcheck"}, e, &out, &errOut); code != 1 {
		t.Fatalf("healthcheck without a server = %d", code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, e, &out, &errOut) }()
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		res, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			res.Body.Close()
			ready = res.StatusCode == http.StatusOK
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		cancel()
		t.Fatalf("the server did not become ready: %q", errOut.String())
	}
	var probe bytes.Buffer
	if code := run(context.Background(), []string{"-healthcheck"}, e, &probe, &probe); code != 0 {
		t.Errorf("healthcheck = %d output = %q", code, probe.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("run = %d output = %q", code, errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
	if !strings.Contains(out.String(), "bootstrap_token") {
		t.Error("the start printed no bootstrap token")
	}
}
