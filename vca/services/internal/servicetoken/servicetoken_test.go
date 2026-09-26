// SPDX-License-Identifier: Apache-2.0

package servicetoken

import (
	"net/http"
	"testing"
)

const secret = "0123456789abcdef0123456789abcdef"

func TestDeriveIsStableAndBoundToThePurpose(t *testing.T) {
	a := Derive(secret, DataSourceLookup)
	if a == "" || a != Derive(secret, DataSourceLookup) {
		t.Fatalf("token %q is not stable", a)
	}
	if a == Derive(secret, "another purpose") {
		t.Fatal("two purposes share one token")
	}
	if a == Derive(secret+"x", DataSourceLookup) {
		t.Fatal("two secrets share one token")
	}
	if len(a) != 43 {
		t.Fatalf("token length %d, want 43 base64url characters", len(a))
	}
}

func TestDeriveRefusesAShortSecret(t *testing.T) {
	for _, s := range []string{"", "short", "  0123456789abcde  "} {
		if got := Derive(s, DataSourceLookup); got != "" {
			t.Errorf("secret %q gave token %q", s, got)
		}
	}
	if Derive(secret, "") != "" {
		t.Error("an empty purpose gave a token")
	}
}

func TestMatches(t *testing.T) {
	want := Derive(secret, DataSourceLookup)
	h := http.Header{}
	if Matches(h, want) {
		t.Fatal("no header matched")
	}
	Set(h, want)
	if h.Get("Authorization") != "Bearer "+want || !Matches(h, want) {
		t.Fatalf("header %q did not match", h.Get("Authorization"))
	}
	h.Set("Authorization", "bearer "+want)
	if !Matches(h, want) {
		t.Fatal("the scheme compares without case")
	}
	h.Set("Authorization", "Bearer "+want+"x")
	if Matches(h, want) {
		t.Fatal("another token matched")
	}
	h.Set("Authorization", "Basic "+want)
	if Matches(h, want) {
		t.Fatal("another scheme matched")
	}
	h.Set("Authorization", "Bearer ")
	if Matches(h, "") {
		t.Fatal("an empty token matched")
	}
}
