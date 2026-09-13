// SPDX-License-Identifier: Apache-2.0

package grants_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/grants"
)

type failStore struct {
	oidcflow.Persister
	fail bool
}

func (f *failStore) Save(name string, v any) error {
	if f.fail {
		return errors.New("fail")
	}
	return f.Persister.Save(name, v)
}

func (f *failStore) Load(name string, v any) error {
	if f.fail {
		return errors.New("fail")
	}
	return f.Persister.Load(name, v)
}

var key = []byte("0123456789abcdef0123456789abcdef")

func TestVault(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := &failStore{Persister: oidcflow.NewMemoryPersister()}
	v, err := grants.New(key, store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New([]byte("short"), nil, nil); err == nil {
		t.Fatal("short key accepted")
	}
	g := grants.Grant{AccessToken: "at-secret", IDToken: "idt", ExpiresAt: now.Add(time.Hour)}
	if err := v.Put("sid1", g); err != nil {
		t.Fatal(err)
	}
	// The persisted document holds no plain token.
	var raw map[string]any
	_ = store.Load("grants", &raw)
	enc, _ := json.Marshal(raw)
	if strings.Contains(string(enc), "at-secret") || strings.Contains(string(enc), "idt") {
		t.Fatal("token stored in plain text")
	}
	got, err := v.Take("sid1", "https://issuer.example")
	if err != nil || got.AccessToken != "at-secret" || got.CredentialIssuer != "https://issuer.example" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := v.Take("sid1", "https://other.example"); !errors.Is(err, grants.ErrBound) {
		t.Fatalf("bound: %v", err)
	}
	if got, err := v.Take("sid1", "https://issuer.example"); err != nil || got.AccessToken != "at-secret" {
		t.Fatalf("again: %v", err)
	}
	if v.IDToken("sid1") != "idt" || v.IDToken("nope") != "" {
		t.Fatal("id token")
	}
	if _, err := v.Take("nope", "x"); !errors.Is(err, grants.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	// A vault with the same key opens the persisted ciphertext.
	v2, err := grants.New(key, store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v2.Take("sid1", ""); err != nil || got.AccessToken != "at-secret" {
		t.Fatalf("reopen: %v", err)
	}
	// A vault with another key cannot.
	v3, _ := grants.New([]byte("fedcba9876543210fedcba9876543210"), store, clock)
	if _, err := v3.Take("sid1", ""); !errors.Is(err, grants.ErrNotFound) {
		t.Fatalf("other key: %v", err)
	}
	// Expiry.
	now = now.Add(2 * time.Hour)
	if _, err := v.Take("sid1", "https://issuer.example"); !errors.Is(err, grants.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if err := v.Put("sid2", grants.Grant{AccessToken: "b", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Take("sid1", ""); !errors.Is(err, grants.ErrNotFound) {
		t.Fatal("expired entry not swept")
	}
	if err := v.Delete("sid2"); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("sid2"); err != nil {
		t.Fatal(err)
	}
	// Persist failures.
	store.fail = true
	if err := v.Put("sid3", g); err == nil {
		t.Fatal("save error hidden")
	}
	if _, err := grants.New(key, store, clock); err == nil {
		t.Fatal("load error hidden")
	}
	store.fail = false
	_ = v.Put("sid4", grants.Grant{AccessToken: "c", ExpiresAt: now.Add(time.Hour)})
	store.fail = true
	if _, err := v.Take("sid4", "https://bind.example"); err == nil {
		t.Fatal("bind save error hidden")
	}
	store.fail = false
	if got, _ := v.Take("sid4", "https://other.example"); got.CredentialIssuer != "https://other.example" {
		t.Fatal("bind not rolled back")
	}
	if err := v.Delete("sid4"); err != nil {
		t.Fatal(err)
	}
	// Corrupt entries.
	corrupt := oidcflow.NewMemoryPersister()
	_ = corrupt.Save("grants", map[string]any{"a": map[string]string{"n": "!!", "d": "x"}, "b": map[string]string{"n": "AAAA", "d": "AAAA"}})
	v4, err := grants.New(key, corrupt, clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"a", "b"} {
		if _, err := v4.Take(sid, ""); !errors.Is(err, grants.ErrNotFound) {
			t.Fatalf("corrupt %s: %v", sid, err)
		}
	}
	if _, err := grants.New(key, nil, nil); err != nil {
		t.Fatal(err)
	}
}
