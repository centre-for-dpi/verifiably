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
	ln.Close()
	return addr
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
	bad := env(map[string]string{"VCA_STATUS_BITSTRING_LIST_SIZE": "8"})
	if code := run(context.Background(), nil, bad, &out, &errOut); code != 1 ||
		!strings.Contains(errOut.String(), "LIST_SIZE") {
		t.Fatalf("bad config: %d %s", code, errOut.String())
	}
	errOut.Reset()
	keyFile := env(map[string]string{"VCA_STATUS_BITSTRING_SIGNING_KEY_FILE": "/nope.pem"})
	if code := run(context.Background(), nil, keyFile, &out, &errOut); code != 1 {
		t.Fatalf("build error: %d", code)
	}
}

func TestRunServesAndHealthchecks(t *testing.T) {
	addr := freePort(t)
	e := env(map[string]string{"VCA_STATUS_BITSTRING_LISTEN": addr})
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
			resp.Body.Close()
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
	badAddr := env(map[string]string{"VCA_STATUS_BITSTRING_LISTEN": "300.0.0.1:x"})
	if code := run(ctx, nil, badAddr, &out, &errOut); code != 1 {
		t.Fatalf("listen error: %d", code)
	}
}
