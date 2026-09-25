// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// brokenKV fails every call after the number of good puts runs out.
type brokenKV struct {
	store.KeyValue
	puts    int
	listErr bool
	getErr  bool
}

var errDisk = errors.New("disk full")

func (b *brokenKV) Put(ctx context.Context, key string, value []byte) error {
	if b.puts <= 0 {
		return errDisk
	}
	b.puts--
	return b.KeyValue.Put(ctx, key, value)
}

func (b *brokenKV) List(ctx context.Context, prefix string) ([]string, error) {
	if b.listErr {
		return nil, errDisk
	}
	return b.KeyValue.List(ctx, prefix)
}

func (b *brokenKV) Get(ctx context.Context, key string) ([]byte, error) {
	if b.getErr && strings.HasPrefix(key, sourcePrefix) {
		return nil, errDisk
	}
	return b.KeyValue.Get(ctx, key)
}

func TestPolicyBoundsAndStorage(t *testing.T) {
	p := DefaultPolicy()
	if p.Refresh(KindTrust) != 6*time.Hour || p.Refresh(KindKeys) != 24*time.Hour || p.Refresh(KindStatus) != time.Hour || p.Refresh("other") != time.Hour {
		t.Fatalf("refresh intervals = %+v", p)
	}
	bad := p
	bad.Window, bad.TrustRefresh = 8*24*time.Hour, time.Second
	checkErr := bad.Check()
	if !errors.Is(checkErr, ErrPolicy) || !strings.Contains(checkErr.Error(), "7 days") || !strings.Contains(checkErr.Error(), "trust_list") {
		t.Fatalf("Check = %v", checkErr)
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("want a fetcher required")
	}
	if _, err := New(Options{Fetch: newWorld(t).fetch, Defaults: bad}); err == nil {
		t.Fatal("want bad defaults refused")
	}
	w := newWorld(t)
	c := w.cache(t, Policy{})
	ctx := context.Background()
	if got := c.Policy(ctx); got.TrustRefresh != 6*time.Hour || got.Window != 24*time.Hour || got.AllowOffline {
		t.Fatalf("a zero default policy = %+v", got)
	}
	if _, err := c.SetPolicy(ctx, bad); !errors.Is(err, ErrPolicy) {
		t.Fatalf("SetPolicy of a bad policy = %v", err)
	}
	stored, setErr := c.SetPolicy(ctx, Policy{AllowOffline: true, Window: 72 * time.Hour})
	if setErr != nil || stored.TrustRefresh != 6*time.Hour || stored.Window != 72*time.Hour {
		t.Fatalf("SetPolicy = %+v, %v", stored, setErr)
	}
	// A new cache on the same store reads the stored policy.
	if again := w.cache(t, offline()).Policy(ctx); again != stored {
		t.Fatalf("stored policy = %+v", again)
	}
	if err := w.kv.Put(ctx, policyKey, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if got := c.Policy(ctx); got.KeysRefresh != 24*time.Hour || got.AllowOffline {
		t.Fatalf("a broken policy file = %+v", got)
	}
	broken := &brokenKV{KeyValue: store.Memory()}
	cb, err := New(Options{KV: broken, Fetch: w.fetch, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cb.SetPolicy(ctx, DefaultPolicy()); !errors.Is(err, errDisk) {
		t.Fatalf("SetPolicy on a full disk = %v", err)
	}
}

func TestStoreFaults(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	broken := &brokenKV{KeyValue: store.Memory()}
	c, err := New(Options{KV: broken, TrustURL: trustURL, Snapshot: w.export, Fetch: w.fetch, Now: w.clock, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sync(ctx, KindTrust); !errors.Is(err, errDisk) {
		t.Fatalf("Sync on a full disk = %v", err)
	}
	if _, err := c.Sync(ctx, KindKeys); !errors.Is(err, errDisk) {
		t.Fatalf("Sync of keys on a full disk = %v", err)
	}
	if ran := c.RunDue(ctx); len(ran) != 1 || ran[0] != KindStatus {
		t.Fatalf("RunDue = %v", ran)
	}
	broken.listErr = true
	if _, err := c.State(ctx); !errors.Is(err, errDisk) {
		t.Fatalf("State with a broken list = %v", err)
	}
	if _, err := c.Sync(ctx, KindStatus); !errors.Is(err, errDisk) {
		t.Fatalf("Sync of status lists with a broken list = %v", err)
	}
	if _, err := c.Sync(ctx, KindKeys); !errors.Is(err, errDisk) {
		t.Fatalf("Sync of keys with a broken list = %v", err)
	}
	if _, err := c.Sync(ctx, "other"); err == nil {
		t.Fatal("want an unknown kind refused")
	}
	// A remembered source that cannot be stored only logs.
	c.remember(ctx, KindStatus, listURL, "")
	broken.listErr, broken.puts = false, 1
	if err := broken.KeyValue.Put(ctx, sourcePrefix+"status_list/x", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	broken.getErr = true
	if _, err := c.State(ctx); !errors.Is(err, errDisk) {
		t.Fatalf("State with a broken read = %v", err)
	}
	broken.getErr = false
	if st, err := c.State(ctx); err != nil || len(st.Sources) != 0 {
		t.Fatalf("a source that does not decode shows: %+v, %v", st.Sources, err)
	}
}

func TestRunStopsWithTheContext(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, time.Millisecond)
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for {
		if s, ok := c.load(context.Background(), KindTrust, trustURL); ok && s.Good() {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run did not read the trust list")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
}

// TestIssuerKeysChecks reads the key set of an https issuer and refuses
// a DID document that names another DID, or keys that do not parse.
func TestIssuerKeysChecks(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	ctx := context.Background()
	w.docs["https://issuer.example/.well-known/jwks.json"] = jwksJSON(t, w.issuer, "k1")
	if s, err := c.issuerKeys(ctx, "https://issuer.example/"); err != nil || s.Items != 1 {
		t.Fatalf("https issuer = %+v, %v", s, err)
	}
	w.docs["https://empty.example/.well-known/jwks.json"] = []byte(`{"keys":[]}`)
	w.docs["https://other.example/.well-known/did.json"] = w.docs[didURL]
	w.docs["https://nokey.example/.well-known/did.json"] = []byte(`{"id":"did:web:nokey.example"}`)
	w.docs["https://broken.example/.well-known/did.json"] = []byte(`not json`)
	for _, issuer := range []string{
		"https://empty.example", "https://missing.example", "did:web:other.example", "did:web:nokey.example",
		"did:web:broken.example", "did:web:missing.example", "did:web:",
	} {
		if _, err := c.issuerKeys(ctx, issuer); err == nil {
			t.Errorf("%s: want a refusal", issuer)
		}
	}
	// An issuer that an online evaluation resolved joins the schedule.
	online := func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, nil }
	if _, err := c.Keys(online)(ctx, "https://issuer.example", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Keys(online)(ctx, "did:key:z6Mk", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sync(ctx, KindKeys); err != nil {
		t.Fatal(err)
	}
	if s := sourceOf(t, c, KindKeys, "https://issuer.example"); !s.Good() || s.Issuer != "https://issuer.example" {
		t.Fatalf("remembered issuer = %+v", s)
	}
	if _, ok := c.load(ctx, KindKeys, "did:key:z6Mk"); ok {
		t.Fatal("a did:key issuer joined the schedule")
	}
}

// TestStatusListShapes stores a JSON status list as not checked and
// refuses tokens that do not parse, name no issuer, or fail.
func TestStatusListShapes(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	ctx := context.Background()
	w.docs["https://s.example/json"] = []byte(`{"issuer":{"id":"did:web:education.go.ke"},"type":["VerifiableCredential"]}`)
	if s, err := c.statusList(ctx, "https://s.example/json"); err != nil || s.SignedBy != NotChecked || s.Issuer != issuerDID {
		t.Fatalf("JSON list = %+v, %v", s, err)
	}
	noIss, err := jose.Sign(w.issuer, issuerKid, "statuslist+jwt", map[string]any{"sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := jose.Sign(w.issuer, "k", "statuslist+jwt", map[string]any{"iss": "did:web:missing.example"})
	if err != nil {
		t.Fatal(err)
	}
	w.docs["https://s.example/bad-json"] = []byte(`{not json`)
	w.docs["https://s.example/garbage"] = []byte(`garbage`)
	w.docs["https://s.example/body"] = []byte(`e30.bm90IGpzb24.c2ln`)
	w.docs["https://s.example/no-iss"] = []byte(noIss)
	w.docs["https://s.example/unknown"] = []byte(unknown)
	for _, u := range []string{
		"https://s.example/bad-json", "https://s.example/garbage", "https://s.example/body",
		"https://s.example/no-iss", "https://s.example/unknown", "https://s.example/missing",
	} {
		if _, err := c.statusList(ctx, u); err == nil {
			t.Errorf("%s: want a refusal", u)
		}
	}
	// A key the issuer rotated passes with a fresh read of its keys.
	if _, err := c.Sync(ctx, ""); err != nil {
		t.Fatal(err)
	}
	w.issuer = mustKey(t)
	w.docs[didURL] = didDocument(t, w.issuer)
	w.docs[listURL] = w.statusList(t, w.issuer, 3)
	if s, err := c.statusList(ctx, listURL); err != nil || s.SignedBy != issuerKid {
		t.Fatalf("a rotated key = %+v, %v", s, err)
	}
	if issuerOf(map[string]any{"issuer": "did:web:a"}) != "did:web:a" || issuerOf(map[string]any{}) != "" {
		t.Fatal("issuerOf")
	}
}

// TestAnchorChains checks a chain of two certificates and refuses a
// chain whose links do not match, or text with no certificate.
func TestAnchorChains(t *testing.T) {
	root, rootKey := certificate(t, nil, nil, "Root")
	leaf, _ := certificate(t, root, rootKey, "Leaf")
	stranger, _ := certificate(t, nil, nil, "Stranger")
	good, err := checkChain(pemOf(leaf)+pemOf(root), t0)
	if err != nil || good.Items != 2 || !strings.Contains(good.SignedBy, "Root") {
		t.Fatalf("a good chain = %+v, %v", good, err)
	}
	for name, text := range map[string]string{
		"broken link": pemOf(leaf) + pemOf(stranger),
		"no pem":      "text",
		"bad der":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})),
		"not yet":     pemOf(root),
	} {
		at := t0
		if name == "not yet" {
			at = t0.Add(-48 * time.Hour)
		}
		if _, err := checkChain(text, at); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

func certificate(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, ok := mustKey(t).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	signer, signerKey := tpl, k
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &k.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, k
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// TestTrustFallbackEdges covers a deployment with no trust registry,
// an unknown issuer, and copies that do not decode.
func TestTrustFallbackEdges(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	none, newErr := New(Options{Fetch: w.fetch, Defaults: offline(), Now: w.clock, Log: quiet})
	if newErr != nil {
		t.Fatal(newErr)
	}
	if failed, err := none.Sync(ctx, ""); err != nil || failed != 0 {
		t.Fatalf("Sync with no registry = %d, %v", failed, err)
	}
	c := w.cache(t, offline())
	if _, err := c.Sync(ctx, ""); err != nil {
		t.Fatal(err)
	}
	down := func(context.Context, string, string) (policy.Trust, error) { return policy.Trust{}, errOffline }
	got, lookErr := c.Trust(down)(ctx, "did:web:nobody.example", degree)
	if lookErr != nil || got.Trusted || got.Reason == "" {
		t.Fatalf("unknown issuer = %+v, %v", got, lookErr)
	}
	// The key set of the registry comes from the copy when the registry
	// does not answer, and the snapshot read fails.
	w.setDown(true)
	if failed := syncN(t, c, KindTrust); failed != 1 {
		t.Fatal("want the trust read to fail")
	}
	if _, err := c.registryKeys(ctx); err != nil {
		t.Fatalf("stored registry keys = %v", err)
	}
	fresh := newWorld(t)
	fresh.setDown(true)
	if _, err := fresh.cache(t, offline()).registryKeys(ctx); err == nil {
		t.Fatal("want no key set without a copy")
	}
	// Copies that do not decode give errors, not answers.
	for _, s := range []Source{
		{Kind: KindTrust, Key: trustURL, Body: []byte("not a token"), SyncedAt: w.clock()},
		{Kind: KindKeys, Key: issuerDID, Body: []byte("not json"), SyncedAt: w.clock()},
	} {
		if err := c.save(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Trust(down)(ctx, issuerDID, degree); err == nil {
		t.Fatal("want a broken snapshot refused")
	}
	keysDown := func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, errOffline }
	if _, err := c.Keys(keysDown)(ctx, issuerDID, ""); err == nil {
		t.Fatal("want broken keys refused")
	}
	if n := c.trustIssuers(ctx); n != 0 {
		t.Fatalf("issuers of a broken snapshot = %d", n)
	}
	if _, err := decodeClaims([]byte("e30.bm90IGpzb24.c2ln")); err == nil {
		t.Fatal("want a payload that does not decode refused")
	}
	raw, err := json.Marshal(Source{Kind: KindKeys})
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
}
