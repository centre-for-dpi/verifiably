// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// longFarmerID is a claim value with no break in it, as long as the
// identityQR text of a Claim 169 credential.
var longFarmerID = "FM-0042-KIAMBU-LIMURU-2026-" + strings.Repeat("Q2xhaW0xNjk", 12)

// layoutPage is one page that the layout script renders.
type layoutPage struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	HTML string `json:"html"`
}

// layout renders the pages at 1280 px in Chromium and returns what
// overflows the content column of each.
func layout(ctx context.Context, t *testing.T, browsers string, pages []layoutPage) map[string][]string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pages": pages})
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("testdata", "layout_e2e.cjs"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "node", script) // #nosec G204 -- a fixed script of the test
	cmd.Env = append(os.Environ(), browsersEnv+"="+browsers)
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(raw), &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("the layout script: %v\n%s", err, stderr.String())
	}
	var seen struct {
		Overflow map[string][]string `json:"overflow"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &seen); err != nil {
		t.Fatalf("the layout script printed %q: %v", stdout.String(), err)
	}
	return seen.Overflow
}

// TestLayout is review finding 7: the pages whose tables clipped at
// 1280 px render in Chromium at that width, and nothing reaches past
// the content column or scrolls inside it. The pages carry a long DID,
// a claim value with no break, and badges at the row ends: the trust
// list, the card of the wallet, the result of a request, the check
// page, the caching page, and the issued list.
func TestLayout(t *testing.T) {
	browsers := needChromium(t)
	api := newWaltidIssuer(t)
	w := newWalk(t, configv1.Dpg_DPG_WALTID, "walt.id Community Stack", map[string]string{"http://waltid-issuer-api:7002": api.srv.URL})
	w.farmerID = longFarmerID
	defer w.begin(4 * budget)()
	w.start()
	overview := w.signIn(w.staff, w.issuer).has(t, "Your issuer on walt.id Community Stack.")
	identity := w.staff.get(overview.link(t, "Set up the identity")).must(t)
	w.staff.submit(identity.form(t, "/identity/provision"), "method", "did:key", "key_type", "Ed25519").must(t)
	w.publish()
	offer, pin := w.issue()
	credential := w.claimInBrowser(offer, pin, "No trust list names")
	w.signIn(w.checker, w.verifier).must(t)
	trust := w.operator.get(w.adminSignIn().link(t, "Trust")).must(t)
	trusted := w.operator.submit(trust.form(t, "/admin/trust/approve")).must(t).has(t, "The entry is active.")
	w.query()
	request := w.request().has(t, "Valid")
	result := w.checker.get(request.link(t, "Open the result")).must(t).has(t, longFarmerID)
	cache := w.checker.get(w.verifier.public + "/portal/cache/").must(t)
	synced := w.checker.submit(cache.form(t, "/portal/cache/sync")).must(t)
	pages := []layoutPage{
		{Name: "trust list", URL: trusted.url.String(), HTML: trusted.body},
		{Name: "wallet card", URL: w.holder.public + "/wallet/", HTML: w.citizen.get(w.holder.public+"/wallet/").must(t).has(t, longFarmerID).body},
		{Name: "request result", URL: result.url.String(), HTML: result.body},
		{Name: "check page", URL: w.verifier.public + "/verify/", HTML: w.check(credential).has(t, longFarmerID).body},
		{Name: "caching", URL: synced.url.String(), HTML: synced.body},
		{Name: "issued list", URL: w.issuer.public + "/issued/", HTML: w.staff.get(w.issuer.public + "/issued/").must(t).body},
	}
	got := layout(w.ctx, t, browsers, pages)
	for _, p := range pages {
		problems, ok := got[p.Name]
		if !ok {
			t.Errorf("%s: the script measured nothing", p.Name)
		}
		if len(problems) > 0 {
			t.Errorf("%s overflows the content column at 1280 px:\n  %s", p.Name, strings.Join(problems, "\n  "))
		}
	}
}
