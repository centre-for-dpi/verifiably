// SPDX-License-Identifier: Apache-2.0

package static_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/static"
)

// harness runs wallet.js in node with an in memory IndexedDB. The script
// prints the public signing key twice, a signature, and what the
// private key allows.
const harness = `
const fs = require("fs");
const vm = require("vm");
const kept = new Map();
function answer(result) {
  const req = {};
  setTimeout(() => { req.result = result; if (req.onsuccess) req.onsuccess(); }, 0);
  return req;
}
const db = {
  createObjectStore() {},
  transaction() {
    return { objectStore() {
      return { get: (id) => answer(kept.get(id)), put: (v, id) => { kept.set(id, v); return answer(undefined); } };
    } };
  },
};
const indexedDB = { open() {
  const req = {};
  setTimeout(() => { req.result = db; if (req.onupgradeneeded) req.onupgradeneeded(); req.onsuccess(); }, 0);
  return req;
} };
const ctx = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, indexedDB });
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx);
(async () => {
  const VCA = vm.runInContext("VCA", ctx);
  const jwk = await VCA.signingJWK();
  const again = await VCA.signingJWK();
  const sig = await VCA.sign("eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4ifQ");
  const pair = await VCA.signingKey();
  let exported = true;
  try { await crypto.subtle.exportKey("jwk", pair.privateKey); } catch (e) { exported = false; }
  console.log(JSON.stringify({ jwk, again, sig, extractable: pair.privateKey.extractable, exported,
    algorithm: pair.privateKey.algorithm, usages: pair.privateKey.usages }));
})().catch((e) => { console.error(e); process.exit(1); });
`

// TestTheBrowserSigningKeyStaysInTheBrowser runs wallet.js in node, the
// one JavaScript engine of the build machine, and checks the signing key
// of ADR-073: an ECDSA P-256 key that no script can export, kept across
// calls, whose ES256 signature a server verifies with the public JWK.
func TestTheBrowserSigningKeyStaysInTheBrowser(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; the walkthrough signs with the same algorithm")
	}
	script, err := static.Script()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	walletPath, harnessPath := filepath.Join(dir, "wallet.js"), filepath.Join(dir, "harness.js")
	if err = os.WriteFile(walletPath, script, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, node, harnessPath, walletPath) // #nosec G204 -- the node binary and two files of the test
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err = cmd.Run(); err != nil {
		t.Fatalf("node: %v\n%s", err, errOut.String())
	}
	var got struct {
		JWK, Again  map[string]any
		Sig         string
		Extractable bool
		Exported    bool
		Algorithm   struct {
			Name       string
			NamedCurve string
		}
		Usages []string
	}
	if err = json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("the harness printed %q: %v", out.String(), err)
	}
	if got.Extractable || got.Exported {
		t.Fatal("a script can read the private signing key")
	}
	if got.Algorithm.Name != "ECDSA" || got.Algorithm.NamedCurve != "P-256" || len(got.Usages) != 1 || got.Usages[0] != "sign" {
		t.Fatalf("private key = %+v %v, want ECDSA P-256 for signing only", got.Algorithm, got.Usages)
	}
	if len(got.JWK) != 4 || got.JWK["kty"] != "EC" || got.JWK["crv"] != "P-256" {
		t.Fatalf("public key = %v, want the members of RFC 7638", got.JWK)
	}
	if got.JWK["x"] != got.Again["x"] || got.JWK["y"] != got.Again["y"] {
		t.Fatal("a second call made a new key; the browser must keep one")
	}
	key, err := jose.JWKFromMap(got.JWK)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := key.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the public key is a %T", key.Key)
	}
	raw, err := base64.RawURLEncoding.DecodeString(got.Sig)
	if err != nil || len(raw) != 64 {
		t.Fatalf("signature of %d bytes, %v; want the 64 bytes of ES256", len(raw), err)
	}
	sum := sha256.Sum256([]byte("eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4ifQ"))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatal("the signature of the browser does not verify with its public key")
	}
}

// bindHarness runs wallet.js in node with a page that asks the browser
// to bind its key, and a portal that answers the two steps. It binds
// once before the key exists, then makes the key, binds twice, and
// prints the posts and the signing key.
const bindHarness = `
const fs = require("fs");
const vm = require("vm");
const kept = new Map();
function answer(result) {
  const req = {};
  setTimeout(() => { req.result = result; if (req.onsuccess) req.onsuccess(); }, 0);
  return req;
}
const db = {
  createObjectStore() {},
  transaction() {
    return { objectStore() {
      return { get: (id) => answer(kept.get(id)), put: (v, id) => { kept.set(id, v); return answer(undefined); } };
    } };
  },
};
const indexedDB = { open() {
  const req = {};
  setTimeout(() => { req.result = db; if (req.onupgradeneeded) req.onupgradeneeded(); req.onsuccess(); }, 0);
  return req;
} };
const status = { dataset: { holderKey: "register" }, textContent: "" };
const document = {
  body: { dataset: {} },
  getElementById: (id) => (id === "wallet-status" ? status : null),
  querySelector: (q) => (q === 'input[name="csrf_token"]' ? { value: "page-token" } : null),
  addEventListener() {},
};
const posts = [];
const input = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJzaWQtMSJ9";
async function fetch(url, opts) {
  posts.push({ url, body: String(opts.body) });
  const body = url.endsWith("/holder-key/proof") ? { signing_input: input } : { thumbprint: "t" };
  return { ok: true, json: async () => body };
}
const ctx = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, indexedDB, document, fetch, URLSearchParams });
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx);
(async () => {
  const VCA = vm.runInContext("VCA", ctx);
  await VCA.wireKey();
  const before = posts.length;
  await VCA.signingJWK();
  await VCA.wireKey();
  const again = await VCA.bindKey();
  console.log(JSON.stringify({ before, posts, again, mark: status.dataset.holderKey, jwk: await VCA.signingJWK(), input }));
})().catch((e) => { console.error(e); process.exit(1); });
`

// TestTheBrowserBindsItsKeyOnce runs the binding of wallet.js in node: a
// page that asks for it gets no post before the browser holds a key, then
// one proof step and one post of the public key with a signature that
// verifies. A second call posts nothing.
func TestTheBrowserBindsItsKeyOnce(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; the portal tests cover the two steps")
	}
	script, err := static.Script()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	walletPath, harnessPath := filepath.Join(dir, "wallet.js"), filepath.Join(dir, "harness.js")
	if err = os.WriteFile(walletPath, script, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(harnessPath, []byte(bindHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, node, harnessPath, walletPath) // #nosec G204 -- the node binary and two files of the test
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err = cmd.Run(); err != nil {
		t.Fatalf("node: %v\n%s", err, errOut.String())
	}
	var got struct {
		Before int
		Posts  []struct{ URL, Body string }
		Again  bool
		Mark   string
		JWK    map[string]any
		Input  string
	}
	if err = json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("the harness printed %q: %v", out.String(), err)
	}
	if got.Before != 0 {
		t.Fatalf("the page posted %d times before the browser held a key", got.Before)
	}
	if len(got.Posts) != 2 || got.Posts[0].URL != "/wallet/holder-key/proof" || got.Posts[1].URL != "/wallet/holder-key" || got.Again || got.Mark != "held" {
		t.Fatalf("posts = %+v, again %v, mark %q", got.Posts, got.Again, got.Mark)
	}
	form, err := url.ParseQuery(got.Posts[1].Body)
	if err != nil || form.Get("csrf_token") != "page-token" {
		t.Fatalf("the post %q carries no page token: %v", got.Posts[1].Body, err)
	}
	key, err := jose.ParseJWK([]byte(form.Get("jwk")))
	var posted map[string]any
	if err != nil || json.Unmarshal([]byte(form.Get("jwk")), &posted) != nil || posted["x"] != got.JWK["x"] || posted["y"] != got.JWK["y"] {
		t.Fatalf("the post names the key %q, want %v: %v", form.Get("jwk"), got.JWK, err)
	}
	pub, ok := key.Key.(*ecdsa.PublicKey)
	raw, err := base64.RawURLEncoding.DecodeString(form.Get("signature"))
	if !ok || err != nil || len(raw) != 64 {
		t.Fatalf("signature %q: %v", form.Get("signature"), err)
	}
	sum := sha256.Sum256([]byte(got.Input))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatal("the proof of the browser does not verify with the key it posted")
	}
}
