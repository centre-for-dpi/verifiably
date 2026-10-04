// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// playwrightEnv turns the browser test on. The CI job of the browser
// test sets it (ADR-004 decision 6).
const playwrightEnv = "VCA_PLAYWRIGHT"

// browsersEnv names the directory of the browsers of Playwright, as
// Playwright itself reads it.
const browsersEnv = "PLAYWRIGHT_BROWSERS_PATH"

// browserDir returns the directory that holds a Chromium of Playwright:
// the directory that PLAYWRIGHT_BROWSERS_PATH names, else the default
// cache of Playwright under home. It also returns the directory it
// looked in last, for the skip message. ok is false when no Chromium
// sits there.
func browserDir(getenv func(string) string, home, goos string) (dir, looked string, ok bool) {
	candidates := []string{}
	if named := strings.TrimSpace(getenv(browsersEnv)); named != "" && named != "0" {
		candidates = append(candidates, named)
	}
	cache := filepath.Join(home, ".cache", "ms-playwright")
	if goos == "darwin" {
		cache = filepath.Join(home, "Library", "Caches", "ms-playwright")
	}
	candidates = append(candidates, cache)
	for _, c := range candidates {
		looked = c
		entries, err := os.ReadDir(c)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "chromium") {
				return c, c, true
			}
		}
	}
	return "", looked, false
}

// TestBrowserDirFindsChromium checks where the browser test looks for
// Chromium: the directory of PLAYWRIGHT_BROWSERS_PATH first, then the
// default cache of Playwright.
func TestBrowserDirFindsChromium(t *testing.T) {
	named, home := t.TempDir(), t.TempDir()
	env := map[string]string{browsersEnv: named}
	getenv := func(k string) string { return env[k] }
	if _, looked, ok := browserDir(getenv, home, "linux"); ok || looked != filepath.Join(home, ".cache", "ms-playwright") {
		t.Fatalf("an empty directory holds a browser, or the search stopped at %s", looked)
	}
	if err := os.MkdirAll(filepath.Join(home, ".cache", "ms-playwright", "chromium-1194"), 0o750); err != nil {
		t.Fatal(err)
	}
	if dir, _, ok := browserDir(getenv, home, "linux"); !ok || dir != filepath.Join(home, ".cache", "ms-playwright") {
		t.Fatalf("the default cache: %s, %v", dir, ok)
	}
	if err := os.MkdirAll(filepath.Join(named, "chromium_headless_shell-1194"), 0o750); err != nil {
		t.Fatal(err)
	}
	if dir, _, ok := browserDir(getenv, home, "linux"); !ok || dir != named {
		t.Fatalf("%s: %s, %v", browsersEnv, dir, ok)
	}
	if _, looked, _ := browserDir(func(string) string { return "" }, home, "darwin"); looked != filepath.Join(home, "Library", "Caches", "ms-playwright") {
		t.Errorf("on darwin the search ends at %s", looked)
	}
}

// chromium runs one phase of testdata/wallet_e2e.cjs in a headless
// Chromium and returns the JSON line it prints.
func chromium(ctx context.Context, t *testing.T, browsers string, input map[string]string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("testdata", "wallet_e2e.cjs"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "node", script, string(raw)) // #nosec G204 -- a fixed script of the test
	// Playwright reads the browsers from the directory the test found.
	cmd.Env = append(os.Environ(), browsersEnv+"="+browsers)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("the %s phase in Chromium: %v\n%s", input["phase"], err, stderr.String())
	}
	var seen map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &seen); err != nil {
		t.Fatalf("the %s phase printed %q: %v", input["phase"], stdout.String(), err)
	}
	if errs, ok := seen["errors"].([]any); ok && len(errs) > 0 {
		t.Errorf("the %s phase hit script errors: %v", input["phase"], errs)
	}
	return seen
}

// TestWalletScriptInChromium runs wallet.js in a real browser against
// the walt.id walkthrough (ADR-004 decision 6, ADR-073). Chromium claims
// the offer: wallet.js makes its signing key in IndexedDB and signs the
// proof. It then binds the key to the wallet, and the keys page names
// the key by its thumbprint. Chromium then answers the request of the verifier: wallet.js
// signs the key binding, and the verifier reads a valid answer. The
// test runs when VCA_PLAYWRIGHT is set; the CI job of the browser test
// sets it and installs Playwright with Chromium. The test finds the
// browser through PLAYWRIGHT_BROWSERS_PATH, or in the default cache of
// Playwright, and a skip names the variable that is missing.
func TestWalletScriptInChromium(t *testing.T) {
	if os.Getenv(playwrightEnv) == "" {
		t.Skip(playwrightEnv + " is not set: set " + playwrightEnv + "=1 to drive wallet.js in Chromium")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	browsers, looked, ok := browserDir(os.Getenv, home, runtime.GOOS)
	if !ok {
		t.Skip(playwrightEnv + " is set, but " + looked + " holds no Chromium of Playwright: set " + browsersEnv +
			" to the directory of the browsers")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip(playwrightEnv + " is set, but node is not on PATH: add the directory of node to PATH")
	}
	api := newWaltidIssuer(t)
	w := newWalk(t, configv1.Dpg_DPG_WALTID, "walt.id Community Stack", map[string]string{"http://waltid-issuer-api:7002": api.srv.URL})
	defer w.begin(4 * budget)()
	ctx := w.ctx
	w.start()
	overview := w.signIn(w.staff, w.issuer).has(t, "Your issuer on walt.id Community Stack.")
	identity := w.staff.get(overview.link(t, "Set up the identity")).must(t)
	w.staff.submit(identity.form(t, "/identity/provision"), "method", "did:key", "key_type", "Ed25519").must(t)
	w.publish()
	offer, pin := w.issue()

	profile := t.TempDir()
	claimed := chromium(ctx, t, browsers, map[string]string{
		"phase": "claim", "holder": w.holder.public, "link": offer, "pin": pin, "profile": profile,
	})
	if claimed["key"] != "EC/P-256" {
		t.Fatalf("wallet.js keeps the signing key %v, want an EC key on P-256", claimed["key"])
	}
	// The page draws its headings in capitals, so the check ignores case.
	page, ok := claimed["page"].(string)
	if !ok || !strings.Contains(strings.ToLower(page), "farmer registration") {
		t.Fatalf("the wallet does not show the claimed credential:\n%s", page)
	}
	if api.onboarded != 1 {
		t.Fatalf("the issuer API onboarded %d keys, want 1", api.onboarded)
	}
	// wallet.js bound its key to the wallet after the claim (ADR-020
	// decision 4), so the keys page names the key by its thumbprint.
	jwk, merr := json.Marshal(claimed["jwk"])
	if merr != nil {
		t.Fatal(merr)
	}
	parsed, perr := jose.ParseJWK(jwk)
	if perr != nil {
		t.Fatalf("the signing key %s: %v", jwk, perr)
	}
	thumbprint, terr := jose.Thumbprint(parsed)
	if terr != nil {
		t.Fatal(terr)
	}
	keys, ok := claimed["keys"].(string)
	if !ok || !strings.Contains(keys, "Your browser holds a key for this wallet.") || !strings.Contains(keys, thumbprint) {
		t.Fatalf("the keys page does not name the key %s of the browser:\n%s", thumbprint, keys)
	}

	// The admin trusts the issuer, and the verifier asks for the
	// credential through a link.
	trust := w.operator.get(w.adminSignIn().link(t, "Trust")).must(t)
	w.operator.submit(trust.form(t, "/admin/trust/approve")).must(t).has(t, "The entry is active.")
	w.signIn(w.checker, w.verifier).must(t)
	w.query()
	form := w.checker.get(w.verifier.public+"/scan/requests/new").must(t).form(t, "/scan/requests/")
	sent := w.checker.submit(form, "through", "vca", "deliver", "link").must(t).has(t, "No wallet has answered yet.")
	link := html.UnescapeString(regexp.MustCompile(`openid4vp://[^"<\s]+`).FindString(sent.body))
	if link == "" {
		t.Fatal("the request page shows no link")
	}
	chromium(ctx, t, browsers, map[string]string{"phase": "present", "holder": w.holder.public, "link": link, "profile": profile})
	deadline := time.Now().Add(10 * time.Second)
	for {
		result := w.checker.get(sent.url.String()).must(t)
		if strings.Contains(text(result.body), "Valid") {
			result.has(t, "the issuer is on an enabled trust list")
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the verifier shows no valid answer:\n%s", tail(text(result.body), 40))
		}
		time.Sleep(200 * time.Millisecond)
	}
}
