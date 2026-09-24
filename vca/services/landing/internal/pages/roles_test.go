// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// mixed runs every role on the first stack, the issuer on the second,
// and a starting verifier on the second. The third stack is absent.
func mixed(role commonv1.Role, d configv1.Dpg) topology.State {
	first, second := dpgs()[0], dpgs()[1]
	switch {
	case d == first:
		return topology.Live
	case d == second && role == commonv1.Role_ROLE_ISSUER:
		return topology.Live
	case d == second && role == commonv1.Role_ROLE_VERIFIER:
		return topology.Starting
	default:
		return topology.Absent
	}
}

// only returns a state function that keeps the named pairs live.
func only(pairs ...string) func(commonv1.Role, configv1.Dpg) topology.State {
	return func(role commonv1.Role, d configv1.Dpg) topology.State {
		for _, p := range pairs {
			if p == topology.PairName(role, d) {
				return topology.Live
			}
		}
		return topology.Absent
	}
}

func TestPickerShowsOnlyLiveRoles(t *testing.T) {
	rec := get(t, newPages(t, snapshot(mixed)), "/roles/", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<h1>How do you want to proceed?</h1>`, `Each role has its own sign in and its own portal.`,
		`<a class="tile" href="/roles/issuer/">`, `<h2>Proceed as issuer</h2>`, `<span class="tile-meta">Available on Alpha Stack and Beta Stack</span>`,
		`<a class="tile" href="/roles/holder/">`, `<span class="tile-meta">Available on Alpha Stack</span>`,
		`<a class="tile" href="/roles/verifier/">`,
		`<section class="cta" id="admin"`, `<h2 id="admin-title">Operating this deployment?</h2>`, `<a class="btn btn-primary" href="/roles/admin/">Proceed as admin</a>`,
		`aria-current="page"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("picker missing %q", want)
		}
	}
	// The starting verifier of the second stack does not count.
	verifier := doc[strings.Index(doc, `href="/roles/verifier/"`):]
	verifier = verifier[:strings.Index(verifier, "</a>")]
	if !strings.Contains(verifier, "Available on Alpha Stack</span>") || strings.Contains(verifier, "Beta") {
		t.Errorf("verifier tile:\n%s", verifier)
	}
	if n := strings.Count(doc, `<a class="tile"`); n != 3 {
		t.Errorf("got %d tiles, want 3", n)
	}
	if t.Failed() {
		t.Log(doc)
	}

	// Without an admin the band is gone; without a holder the tile is gone.
	first := dpgs()[0]
	doc = get(t, newPages(t, snapshot(only(topology.PairName(commonv1.Role_ROLE_ISSUER, first), topology.PairName(commonv1.Role_ROLE_VERIFIER, first)))), "/roles/", false).Body.String()
	a11ytest.AssertPage(t, doc)
	if strings.Contains(doc, `class="cta"`) || strings.Contains(doc, "/roles/holder/") || strings.Count(doc, `<a class="tile"`) != 2 {
		t.Errorf("picker with two roles:\n%s", doc)
	}

	// With no live role the picker says so and links back.
	rec = get(t, newPages(t, snapshot(func(commonv1.Role, configv1.Dpg) topology.State { return topology.Absent })), "/roles/", false)
	a11ytest.AssertPage(t, rec.Body.String())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No role runs yet.") || !strings.Contains(rec.Body.String(), `href="/"`) || strings.Contains(rec.Body.String(), `class="tile"`) {
		t.Errorf("empty picker: %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestPickerSkipsWithOneRole(t *testing.T) {
	first := dpgs()[0]
	for pair, want := range map[string]string{
		topology.PairName(commonv1.Role_ROLE_ISSUER, first): "/roles/issuer/",
		topology.PairName(commonv1.Role_ROLE_ADMIN, first):  "/roles/admin/",
	} {
		rec := get(t, newPages(t, snapshot(only(pair))), "/roles/", false)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
			t.Errorf("%s: status %d, location %q", pair, rec.Code, rec.Header().Get("Location"))
		}
	}
	// One role on two stacks still skips the picker.
	rec := get(t, newPages(t, snapshot(only(topology.PairName(commonv1.Role_ROLE_HOLDER, first), topology.PairName(commonv1.Role_ROLE_HOLDER, dpgs()[1])))), "/roles/", false)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/roles/holder/" {
		t.Errorf("one role on two stacks: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestIntroStepsPerRole(t *testing.T) {
	h := newPages(t, snapshot(allLive))
	for role, want := range map[string]struct {
		title string
		steps int
		lead  string
		texts []string
	}{
		"issuer":   {"Issue credentials, step by step.", 4, "Four steps on this deployment.", []string{"Identify your organisation", "Define what you issue", "Deliver by OID4VCI.", "Manage what you issued"}},
		"holder":   {"Hold and present credentials, step by step.", 4, "Four steps on this deployment.", []string{"Discover offers", "Claim a credential", "Present it", "Review what you hold"}},
		"verifier": {"Check credentials, step by step.", 4, "Four steps on this deployment.", []string{"Discover schemas", "Compose a DCQL query. Older wallets take a DIF Presentation Exchange query.", "Receive a presentation", "Check the result"}},
		"admin":    {"Run the deployment, step by step.", 5, "Five steps on this deployment.", []string{"Set who to trust", "Connect trust registries", "Set up sign in", "Add tenants", "Keys and audit"}},
	} {
		rec := get(t, h, "/roles/"+role+"/", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", role, rec.Code)
		}
		doc := rec.Body.String()
		a11ytest.AssertPage(t, doc)
		if !strings.Contains(doc, "<h1>"+want.title+"</h1>") || !strings.Contains(doc, want.lead) {
			t.Errorf("%s: title or lead missing:\n%s", role, doc)
		}
		if n := strings.Count(doc, `<li class="step"`); n != want.steps {
			t.Errorf("%s: got %d steps, want %d", role, n, want.steps)
		}
		for _, text := range want.texts {
			if !strings.Contains(doc, text) {
				t.Errorf("%s: step text %q missing", role, text)
			}
		}
		if !strings.Contains(doc, `<a href="/roles/" hx-get="/roles/"`) || !strings.Contains(doc, ">All roles</a>") {
			t.Errorf("%s: no link back to the picker", role)
		}
		if !strings.Contains(doc, "Sign in to continue") {
			t.Errorf("%s: no sign in section", role)
		}
	}

	// The steps follow the live features. Without a stack that lists the
	// Presentation Exchange protocol, the verifier step names DCQL alone.
	// Without tenancy the admin has four steps. A holder alone, with no
	// issuer to discover, has three. An issuer whose stack prints a QR on
	// a PDF names it.
	first := dpgs()[0]
	third := dpgs()[2]
	custom := snapshot(only(
		topology.PairName(commonv1.Role_ROLE_VERIFIER, third),
		topology.PairName(commonv1.Role_ROLE_ADMIN, first),
		topology.PairName(commonv1.Role_ROLE_HOLDER, first),
		topology.PairName(commonv1.Role_ROLE_ISSUER, first),
	))
	for i := range custom.Peers {
		st := &custom.Peers[i]
		if st.Capabilities == nil {
			continue
		}
		st.Capabilities.Protocols = nil
		st.Capabilities.Features = nil
		if st.Peer.Role == commonv1.Role_ROLE_ISSUER {
			st.Capabilities.Channels = append(st.Capabilities.Channels, backendPDF())
		}
	}
	h = newPages(t, custom)
	doc := get(t, h, "/roles/verifier/", false).Body.String()
	if strings.Contains(doc, "Presentation Exchange") || !strings.Contains(doc, "Compose a DCQL query.") {
		t.Errorf("verifier without PE:\n%s", doc)
	}
	doc = get(t, h, "/roles/admin/", false).Body.String()
	if strings.Count(doc, `<li class="step"`) != 4 || strings.Contains(doc, "Add tenants") || !strings.Contains(doc, "Four steps") {
		t.Errorf("admin without tenancy:\n%s", doc)
	}
	doc = get(t, h, "/roles/issuer/", false).Body.String()
	if !strings.Contains(doc, "Print a QR on a PDF") {
		t.Errorf("issuer with a PDF channel:\n%s", doc)
	}
	alone := newPages(t, snapshot(only(topology.PairName(commonv1.Role_ROLE_HOLDER, first))))
	doc = get(t, alone, "/roles/holder/", false).Body.String()
	if strings.Count(doc, `<li class="step"`) != 3 || strings.Contains(doc, "Discover offers") || !strings.Contains(doc, "Three steps") {
		t.Errorf("holder alone:\n%s", doc)
	}
}

func TestIntroStackChoiceWithTwoStacks(t *testing.T) {
	first, second := dpgs()[0], dpgs()[1]
	issuerA, issuerB := topology.PairName(commonv1.Role_ROLE_ISSUER, first), topology.PairName(commonv1.Role_ROLE_ISSUER, second)
	doc := get(t, newPages(t, snapshot(only(issuerA, issuerB))), "/roles/issuer/", false).Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<h2 id="signin-title">Sign in to continue</h2>`, `Each stack signs you in on its own pair.`,
		`<a class="btn btn-primary" href="https://` + issuerA + `.labs.example/auth/?return_to=%2Fportal%2F">Continue on Alpha Stack</a>`,
		`<a class="btn btn-secondary" href="https://` + issuerB + `.labs.example/auth/?return_to=%2Fportal%2F">Continue on Beta Stack</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("two stacks missing %q\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "Continue to sign in") {
		t.Error("two stacks give a list, not one button")
	}
	// One stack gives one button.
	doc = get(t, newPages(t, snapshot(only(issuerA))), "/roles/issuer/", false).Body.String()
	if !strings.Contains(doc, `<a class="btn btn-primary" href="https://`+issuerA+`.labs.example/auth/?return_to=%2Fportal%2F">Continue to sign in</a>`) || strings.Contains(doc, "Continue on") {
		t.Errorf("one stack:\n%s", doc)
	}
	// The holder returns to the wallet.
	holder := topology.PairName(commonv1.Role_ROLE_HOLDER, first)
	doc = get(t, newPages(t, snapshot(only(holder))), "/roles/holder/", false).Body.String()
	if !strings.Contains(doc, `href="https://`+holder+`.labs.example/auth/?return_to=%2Fwallet%2F"`) {
		t.Errorf("holder sign in:\n%s", doc)
	}
}

// TestIntroNamesTheRealmFromProvidersJSON is P1-08: with one live stack
// the sign in band names the provider and the realm that the auth
// service of the pair lists in /auth/providers.json, and offers to
// register when the provider does. Without the listing, or with an
// empty one, the sentence omits the realm. The admin pair has no auth
// service, so the landing asks its home service.
func TestIntroNamesTheRealmFromProvidersJSON(t *testing.T) {
	first := dpgs()[0]
	issuer := topology.PairName(commonv1.Role_ROLE_ISSUER, first)
	admin := topology.PairName(commonv1.Role_ROLE_ADMIN, first)
	holder := topology.PairName(commonv1.Role_ROLE_HOLDER, first)
	var asked []string
	listings := map[string]signin.Listing{
		"http://" + issuer + "-auth:8081": {Role: "issuer", Providers: []signin.Entry{{ID: "default", DisplayName: "Keycloak", Realm: "vca-issuer-realm", Register: true}}},
		"http://" + admin + "-home:8080":  {Role: "admin", Providers: []signin.Entry{{ID: "idp", DisplayName: "Identity Server", Register: false}}},
		"http://" + holder + "-auth:8081": {Role: "holder"},
	}
	source := func(_ context.Context, base string) (signin.Listing, error) {
		asked = append(asked, base)
		l, ok := listings[base]
		if !ok {
			return signin.Listing{}, errors.New("unreachable")
		}
		return l, nil
	}
	h := newPagesWith(t, snapshot(only(issuer, admin, holder, topology.PairName(commonv1.Role_ROLE_VERIFIER, first))), source)
	doc := get(t, h, "/roles/issuer/", false).Body.String()
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "This deployment signs issuers in through Keycloak in the realm vca-issuer-realm. You can register if you have no account.") {
		t.Errorf("issuer band:\n%s", doc)
	}
	doc = get(t, h, "/roles/admin/", false).Body.String()
	if !strings.Contains(doc, "This deployment signs admins in through Identity Server.</p>") || strings.Contains(doc, "You can register") {
		t.Errorf("admin band:\n%s", doc)
	}
	// An empty listing and an unreachable service keep the plain lead.
	for _, path := range []string{"/roles/holder/", "/roles/verifier/"} {
		doc = get(t, h, path, false).Body.String()
		if !strings.Contains(doc, "Each stack signs you in on its own pair.") || strings.Contains(doc, "signs holders in") || strings.Contains(doc, "signs verifiers in") {
			t.Errorf("%s band:\n%s", path, doc)
		}
	}
	if strings.Join(asked, " ") != "http://"+issuer+"-auth:8081 http://"+admin+"-home:8080 http://"+holder+"-auth:8081 http://"+topology.PairName(commonv1.Role_ROLE_VERIFIER, first)+"-auth:8081" {
		t.Errorf("asked %v", asked)
	}
	// Two live stacks keep the plain lead: the realm differs per stack.
	second := dpgs()[1]
	two := newPagesWith(t, snapshot(only(issuer, topology.PairName(commonv1.Role_ROLE_ISSUER, second))), source)
	doc = get(t, two, "/roles/issuer/", false).Body.String()
	if strings.Contains(doc, "vca-issuer-realm") || !strings.Contains(doc, "Each stack signs you in on its own pair.") {
		t.Errorf("two stacks:\n%s", doc)
	}
}

func TestIntroUnknownRole404(t *testing.T) {
	h := newPages(t, snapshot(allLive))
	for _, path := range []string{"/roles/pilot/", "/roles/issuer/x/", "/roles/ISSUER/"} {
		rec := get(t, h, path, false)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d", path, rec.Code)
		}
		a11ytest.AssertPage(t, rec.Body.String())
	}
	// A missing final slash redirects to the page.
	if rec := get(t, h, "/roles/issuer", false); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/roles/issuer/" {
		t.Errorf("no final slash: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestIntroRoleNotLiveShowsBackLink(t *testing.T) {
	first := dpgs()[0]
	h := newPages(t, snapshot(only(topology.PairName(commonv1.Role_ROLE_ISSUER, first))))
	rec := get(t, h, "/roles/verifier/", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "This deployment runs no verifier yet. Pick another role.") || !strings.Contains(doc, `href="/roles/"`) {
		t.Errorf("verifier page:\n%s", doc)
	}
	if strings.Contains(doc, `<li class="step"`) || strings.Contains(doc, "Sign in to continue") {
		t.Error("a role that does not run shows no steps and no sign in")
	}
	// A starting pair is not live either.
	starting := snapshot(func(role commonv1.Role, d configv1.Dpg) topology.State {
		if role == commonv1.Role_ROLE_HOLDER && d == first {
			return topology.Starting
		}
		return topology.Absent
	})
	doc = get(t, newPages(t, starting), "/roles/holder/", false).Body.String()
	if !strings.Contains(doc, "This deployment runs no holder yet.") {
		t.Errorf("starting holder:\n%s", doc)
	}
}
