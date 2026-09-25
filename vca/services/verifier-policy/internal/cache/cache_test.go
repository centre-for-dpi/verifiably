// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/trustsnap"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/ports"
)

const (
	trustURL  = "http://trust-registry:8085"
	jwksURL   = trustURL + "/.well-known/jwks.json"
	issuerDID = "did:web:education.go.ke"
	didURL    = "https://education.go.ke/.well-known/did.json"
	listURL   = "https://education.go.ke/status/1"
	issuerKid = issuerDID + "#key-1"
	degree    = "UniversityDegree"
)

var t0 = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

// quiet drops the log lines of the failed reads the tests cause.
var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// world is the network the cache reads: the trust registry, the DID
// document of one issuer, and its status list. down cuts it off.
type world struct {
	t        *testing.T
	mu       sync.Mutex
	now      time.Time
	down     bool
	docs     map[string][]byte
	registry crypto.PrivateKey
	issuer   crypto.PrivateKey
	snapshot string
	kv       store.KeyValue
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, now: t0, docs: map[string][]byte{}, kv: store.Memory()}
	w.registry = mustKey(t)
	w.issuer = mustKey(t)
	w.docs[jwksURL] = jwksJSON(t, w.registry, "registry-key")
	w.docs[didURL] = didDocument(t, w.issuer)
	w.docs[listURL] = w.statusList(t, w.issuer, -1)
	w.snapshot = w.sign(t, w.registry, "registry-key", w.claims(""))
	return w
}

func mustKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	k, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwksJSON(t *testing.T, key crypto.PrivateKey, kid string) []byte {
	t.Helper()
	pub, err := jose.PublicJWK(key, kid)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JWKS{Keys: []jose.JWK{pub}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func didDocument(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	pub, err := jose.PublicJWK(key, "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.JWKToMap(pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"id": issuerDID,
		"verificationMethod": []any{map[string]any{
			"id": issuerKid, "type": "JsonWebKey2020", "controller": issuerDID, "publicKeyJwk": m,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// statusList signs a Bitstring status list with one bit set, or none.
func (w *world) statusList(t *testing.T, key crypto.PrivateKey, set int) []byte {
	t.Helper()
	l := bitstring.New(bitstring.MinSize)
	if set >= 0 {
		if err := l.Set(set, true); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := jose.Sign(key, issuerKid, "vc+jwt", bitstring.Credential(listURL, issuerDID, bitstring.Revocation, l, w.now))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(tok)
}

// claims is a snapshot with the issuer on the local list and, with a
// chain, one external registry pinned by an X.509 certificate.
func (w *world) claims(chain string) trustsnap.Claims {
	c := trustsnap.Claims{
		Issuer: trustURL, IssuedAt: w.now.Unix(), ExpiresAt: w.now.Add(24 * time.Hour).Unix(),
		Lists: []trustsnap.List{{
			ListURL: trustURL + "/trust-list/etsi.jws", SignedBy: "registry-key", CheckedAt: w.now,
			Entities: []trustsnap.Entity{{
				Name: "Ministry of Education", Role: trustsnap.RoleIssuer, Status: trustsnap.StatusActive,
				Identities: []trustsnap.Identity{{DID: issuerDID}}, CredentialTypes: []string{degree},
				StatusListEndpoints: []string{listURL},
			}},
		}},
	}
	if chain != "" {
		c.Lists = append(c.Lists, trustsnap.List{
			RegistryID: "reg-ke", RegistryName: "Kenya trust registry", ListURL: "https://trust.go.ke/list.jws",
			SignedBy: "CN=Kenya trust list signer", CheckedAt: w.now, X509Chain: chain,
		})
	}
	return c
}

func (w *world) sign(t *testing.T, key crypto.PrivateKey, kid string, c trustsnap.Claims) string {
	t.Helper()
	tok, err := jose.Sign(key, kid, trustsnap.Type, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (w *world) clock() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

func (w *world) advance(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.now = w.now.Add(d)
}

func (w *world) setDown(down bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.down = down
}

var errOffline = errors.New("no network")

func (w *world) fetch(_ context.Context, url string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.down {
		return nil, errOffline
	}
	body, ok := w.docs[url]
	if !ok {
		return nil, errors.New("404")
	}
	return body, nil
}

func (w *world) export(context.Context) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.down {
		return "", errOffline
	}
	return w.snapshot, nil
}

// cache builds a cache over the world with pol.
func (w *world) cache(t *testing.T, pol Policy) *Cache {
	t.Helper()
	c, err := New(Options{KV: w.kv, TrustURL: trustURL, Snapshot: w.export, Fetch: w.fetch, Defaults: pol, Now: w.clock, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// offline is the default policy with checks allowed with no network.
func offline() Policy {
	p := DefaultPolicy()
	p.AllowOffline = true
	return p
}

// context returns the check context of an evaluation that reads the
// world through the cache.
func (w *world) context(c *Cache) policy.Context {
	online := ports.Keys(did.NewResolver(did.Fetcher(w.fetch), nil), w.fetch)
	trust := func(ctx context.Context, issuer, typ string) (policy.Trust, error) {
		if _, err := w.fetch(ctx, jwksURL); err != nil {
			return policy.Trust{}, err
		}
		return policy.Trust{Trusted: true, DisplayName: "Ministry of Education"}, nil
	}
	return policy.Context{
		Now: w.clock(), Keys: c.Keys(online), Status: c.Status(w.fetch), Trust: c.Trust(trust),
	}
}

// degreeCredential is a JWT credential of the issuer with a status entry.
func (w *world) degreeCredential(t *testing.T) policy.Credential {
	t.Helper()
	tok, err := jose.Sign(w.issuer, issuerKid, "JWT", map[string]any{
		"iss": issuerDID,
		"vc": map[string]any{
			"type": []any{"VerifiableCredential", degree}, "issuer": issuerDID,
			"credentialSubject": map[string]any{"id": "did:key:holder", "degree": "BSc"},
			"credentialStatus":  bitstring.Entry(listURL, 3, bitstring.Revocation),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := vc.Parse([]byte(tok))
	if err != nil {
		t.Fatal(err)
	}
	return policy.Credential{Format: vc.FormatJWT, Token: tok, VC: parsed}
}

// evaluate runs the status and trust checks with the mandatory ones.
func (w *world) evaluate(t *testing.T, c *Cache, mode string) (policy.Report, *Usage) {
	t.Helper()
	ctx, use := Track(context.Background())
	pc := w.context(c)
	set := policy.Set{ID: "degree", Version: 1, Settings: []policy.Setting{
		{Name: policy.NameStatus, Blocking: true, Params: map[string]string{policy.ParamFailMode: mode}},
		{Name: policy.NameTrustChain, Blocking: true},
	}}
	return policy.Evaluate(ctx, policy.Presentation{Credentials: []policy.Credential{w.degreeCredential(t)}}, pc, set), use
}

// result returns the first result of the named check.
func result(t *testing.T, r policy.Report, name string) policy.CheckResult {
	t.Helper()
	for _, c := range r.Results {
		if c.Name == name && c.CredentialIndex == 0 {
			return c
		}
	}
	t.Fatalf("no %s result in %+v", name, r.Results)
	return policy.CheckResult{}
}

func sourceOf(t *testing.T, c *Cache, kind Kind, key string) Source {
	t.Helper()
	state, err := c.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range state.Sources {
		if s.Kind == kind && s.Key == key {
			return s
		}
	}
	t.Fatalf("no %s source %s in %+v", kind, key, state.Sources)
	return Source{}
}

// selfSigned returns a PEM certificate valid around t0.
func selfSigned(t *testing.T, notAfter time.Time) string {
	t.Helper()
	k := mustKey(t)
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Kenya trust list anchor"},
		NotBefore: t0.Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestSyncStoresVerifiedSnapshot reads every kind once. Each copy
// carries what checked it.
func TestSyncStoresVerifiedSnapshot(t *testing.T) {
	w := newWorld(t)
	w.snapshot = w.sign(t, w.registry, "registry-key", w.claims(selfSigned(t, t0.Add(365*24*time.Hour))))
	c := w.cache(t, offline())
	failed, err := c.Sync(context.Background(), "")
	if err != nil || failed != 0 {
		t.Fatalf("Sync = %d, %v", failed, err)
	}
	trust := sourceOf(t, c, KindTrust, trustURL)
	if !trust.SyncedAt.Equal(t0) || trust.SignedBy != "registry-key" || trust.Items != 1 || trust.LastError != "" {
		t.Fatalf("trust source = %+v", trust)
	}
	if k := sourceOf(t, c, KindKeys, jwksURL); k.Items != 1 || !k.Good() {
		t.Fatalf("registry key set = %+v", k)
	}
	if k := sourceOf(t, c, KindKeys, issuerDID); k.Items != 1 || k.SignedBy != issuerDID || k.RegistryName != "" {
		t.Fatalf("issuer keys = %+v", k)
	}
	chain := sourceOf(t, c, KindKeys, "x509:reg-ke")
	if chain.Items != 1 || chain.RegistryName != "Kenya trust registry" || chain.RegistryID != "reg-ke" ||
		!strings.Contains(chain.SignedBy, "Kenya trust list anchor") {
		t.Fatalf("anchor chain = %+v", chain)
	}
	if s := sourceOf(t, c, KindStatus, listURL); s.SignedBy != issuerKid || s.Issuer != issuerDID || !s.Good() {
		t.Fatalf("status list = %+v", s)
	}
	state, err := c.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[Kind][3]int{KindTrust: {1, 1, 1}, KindKeys: {3, 3, 1}, KindStatus: {1, 1, 1}}
	for _, k := range state.Kinds {
		got := [3]int{k.Sources, k.Items, k.Issuers}
		if got != want[k.Kind] || k.Failed != 0 || !k.SyncedAt.Equal(t0) {
			t.Errorf("%s = %+v, want %v", k.Kind, k, want[k.Kind])
		}
	}
}

// TestSyncRejectsBadSignature refuses a snapshot and a status list that
// another key signed, and an anchor chain that expired. The last good
// copies stay.
func TestSyncRejectsBadSignature(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	ctx := context.Background()
	if failed, err := c.Sync(ctx, ""); err != nil || failed != 0 {
		t.Fatalf("first Sync = %d, %v", failed, err)
	}
	good := sourceOf(t, c, KindTrust, trustURL)
	goodList := sourceOf(t, c, KindStatus, listURL)
	w.advance(time.Hour)
	intruder := mustKey(t)
	bad := w.claims(selfSigned(t, t0.Add(30*time.Minute)))
	bad.Lists[0].Entities[0].Status = "revoked"
	w.snapshot = w.sign(t, intruder, "registry-key", bad)
	w.docs[listURL] = w.statusList(t, intruder, 3)
	failed, err := c.Sync(ctx, KindTrust)
	if err != nil || failed != 1 {
		t.Fatalf("Sync of a bad snapshot = %d, %v", failed, err)
	}
	after := sourceOf(t, c, KindTrust, trustURL)
	if after.LastError == "" || !after.SyncedAt.Equal(good.SyncedAt) || string(after.Body) != string(good.Body) || !after.ReadAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("the bad snapshot replaced the good copy: %+v", after)
	}
	if failed := syncN(t, c, KindStatus); failed != 1 {
		t.Fatalf("Sync of a bad status list = %d", failed)
	}
	list := sourceOf(t, c, KindStatus, listURL)
	if list.LastError == "" || string(list.Body) != string(goodList.Body) {
		t.Fatalf("the bad status list replaced the good copy: %+v", list)
	}
	// An anchor chain that expired is refused too. Its registry comes
	// from a good snapshot.
	w.snapshot = w.sign(t, w.registry, "registry-key", bad)
	if failed := syncN(t, c, KindTrust); failed != 0 {
		t.Fatalf("Sync of a good snapshot failed")
	}
	if failed := syncN(t, c, KindKeys); failed != 1 {
		t.Fatalf("Sync of an expired chain = %d", failed)
	}
	if chain := sourceOf(t, c, KindKeys, "x509:reg-ke"); chain.Good() || chain.LastError == "" {
		t.Fatalf("an expired chain was stored: %+v", chain)
	}
	// A failed read of the network keeps every copy.
	w.setDown(true)
	if failed := syncN(t, c, ""); failed < 3 {
		t.Fatalf("Sync with no network = %d failures", failed)
	}
	if s := sourceOf(t, c, KindStatus, listURL); !s.Good() || s.LastError == "" {
		t.Fatalf("a failed read dropped the copy: %+v", s)
	}
}

// TestEvaluateOfflineWithinWindowUsesCache answers from the copies when
// the network is down, inside the window, and reports their age.
func TestEvaluateOfflineWithinWindowUsesCache(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	if _, err := c.Sync(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	online, use := w.evaluate(t, c, policy.FailClosed)
	if online.Verdict != policy.Valid {
		t.Fatalf("online verdict = %s: %+v", online.Verdict, online.Results)
	}
	if _, used := use.Age(); used {
		t.Fatal("an online evaluation reports cached material")
	}
	w.setDown(true)
	w.advance(2 * time.Hour)
	report, use := w.evaluate(t, c, policy.FailClosed)
	if report.Verdict != policy.Valid {
		t.Fatalf("offline verdict = %s: %+v", report.Verdict, report.Results)
	}
	age, used := use.Age()
	if !used || age != 2*time.Hour {
		t.Fatalf("want the material age of 2h, got %v %v", age, used)
	}
	// The status list refreshes every hour, so its copy is stale.
	if !use.Stale() {
		t.Fatal("want the result marked stale")
	}
	if trust := result(t, report, policy.NameTrustChain); trust.Evidence["issuer_name"] != "Ministry of Education" {
		t.Fatalf("trust from the cache = %+v", trust)
	}
	// Without the offline policy the copies stay unused.
	p := DefaultPolicy()
	if _, err := c.SetPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	report, use = w.evaluate(t, c, policy.FailClosed)
	if _, used := use.Age(); used || report.Verdict == policy.Valid {
		t.Fatalf("offline checks ran with the policy off: %s", report.Verdict)
	}
}

// TestEvaluateOfflineBeyondWindowFails fails every check that needs a
// copy older than the window.
func TestEvaluateOfflineBeyondWindowFails(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	if _, err := c.Sync(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	w.setDown(true)
	w.advance(25 * time.Hour)
	report, use := w.evaluate(t, c, policy.FailClosed)
	if report.Verdict != policy.Invalid {
		t.Fatalf("verdict = %s", report.Verdict)
	}
	for _, name := range []string{policy.NameSignature, policy.NameTrustChain, policy.NameStatus} {
		if r := result(t, report, name); r.Result != policy.Fail || r.Evidence["stale"] != "true" {
			t.Errorf("%s = %+v", name, r)
		}
	}
	if _, used := use.Age(); used {
		t.Fatal("a refused copy counts as used")
	}
}

// TestStaleStatusRefusedWhenPolicySaysSo fails the status check on a
// status list older than the window, even in fail open mode. With the
// setting off, the fail mode decides.
func TestStaleStatusRefusedWhenPolicySaysSo(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	ctx := context.Background()
	if _, err := c.Sync(ctx, ""); err != nil {
		t.Fatal(err)
	}
	w.advance(20 * time.Hour)
	if _, err := c.Sync(ctx, KindTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sync(ctx, KindKeys); err != nil {
		t.Fatal(err)
	}
	w.setDown(true)
	w.advance(5 * time.Hour)
	report, _ := w.evaluate(t, c, policy.FailOpen)
	if s := result(t, report, policy.NameStatus); s.Result != policy.Fail || s.Evidence["stale"] != "true" {
		t.Fatalf("status = %+v", s)
	}
	if sig := result(t, report, policy.NameSignature); sig.Result != policy.Pass {
		t.Fatalf("signature from a copy inside the window = %+v", sig)
	}
	p := offline()
	p.RefuseStaleStatus = false
	if _, err := c.SetPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	report, _ = w.evaluate(t, c, policy.FailOpen)
	if s := result(t, report, policy.NameStatus); s.Result != policy.Error {
		t.Fatalf("status in fail open mode = %+v", s)
	}
}

// TestSchedulerRespectsIntervals reads each kind on its own interval.
func TestSchedulerRespectsIntervals(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	ctx := context.Background()
	steps := []struct {
		after time.Duration
		want  []Kind
	}{
		{0, []Kind{KindTrust, KindKeys, KindStatus}},
		{30 * time.Minute, nil},
		{30 * time.Minute, []Kind{KindStatus}},
		{5 * time.Hour, []Kind{KindTrust, KindStatus}},
		{12 * time.Hour, []Kind{KindTrust, KindStatus}},
		{6 * time.Hour, []Kind{KindTrust, KindKeys, KindStatus}},
	}
	for i, s := range steps {
		w.advance(s.after)
		got := c.RunDue(ctx)
		if strings.Join(kindWords(got), ",") != strings.Join(kindWords(s.want), ",") {
			t.Fatalf("step %d: ran %v, want %v", i, got, s.want)
		}
	}
	state, err := c.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range state.Kinds {
		if k.NextSync.IsZero() || !k.NextSync.After(w.clock()) {
			t.Errorf("%s: next sync %v is not after now", k.Kind, k.NextSync)
		}
	}
}

func kindWords(kinds []Kind) []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

// syncN reads kind and returns the failures. A store fault fails the test.
func syncN(t *testing.T, c *Cache, kind Kind) int {
	t.Helper()
	n, err := c.Sync(context.Background(), kind)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
