// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"context"
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/cli"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
)

// farmerSchema is the JSON Schema of the credential the issuer offers.
const farmerSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Farmer registration",
  "type": "object",
  "properties": {
    "fullName": {"type": "string", "title": "Full name"},
    "farmerID": {"type": "string", "title": "Farmer number"},
    "county": {"type": "string", "title": "County"}
  },
  "required": ["fullName", "farmerID", "county"]
}`

// budget is the time one walkthrough may take, from the start of the
// processes to the last verdict (P7-05).
const budget = 30 * time.Second

// walk is one walkthrough: the deployment, its four pairs, and the
// browser of each person.
type walk struct {
	t   *testing.T
	ctx context.Context
	d   *deployment
	// stack is the name the adapter reports for the DPG.
	stack                             string
	issuer, holder, verifier, admin   *runningPair
	staff, citizen, checker, operator *browser
	// key is the signing key that wallet.js keeps in the browser of the
	// farmer (ADR-073).
	key holderKey
}

// newWalk prepares the four pairs of one DPG. The holder pair names no
// DPG wallet, so the credentials stay in the browser store. Setup of a
// laptop deployment lets the wallet read the requests of the verifier
// on this host, and the discovery service read the pairs over plain
// http on the loopback address (docs/verifier-discovery.md).
//
// It builds the commands of the services. The context of the walk
// starts later, in begin, so the build takes none of its time.
func newWalk(t *testing.T, dpg configv1.Dpg, stack string, dpgURLs map[string]string) *walk {
	t.Helper()
	var pairs []cli.Pair
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER, commonv1.Role_ROLE_ADMIN} {
		pairs = append(pairs, cli.Pair{Role: role, Dpg: dpg})
	}
	d := newDeployment(t, pairs, dpgURLs)
	holder := pairs[1].Name()
	d.set(holder, "VCA_WALLET_PORTAL_DPG_ADAPTERS", "")
	d.set(holder, "VCA_WALLET_AUTH_HOLDER_BACKEND_URL", "")
	w := &walk{t: t, d: d, stack: stack, key: newHolderKey(t)}
	for role, claims := range map[commonv1.Role]map[string]any{
		commonv1.Role_ROLE_ISSUER:   {"name": "Amina Odhiambo", "realm_access": map[string]any{"roles": []string{"issuer-admin"}}},
		commonv1.Role_ROLE_HOLDER:   {"name": "Wanjiku Njeri"},
		commonv1.Role_ROLE_VERIFIER: {"name": "Otieno Kamau", "realm_access": map[string]any{"roles": []string{"verifier-admin"}}},
		commonv1.Role_ROLE_ADMIN:    {"name": "Achieng Otieno"},
	} {
		for k, v := range claims {
			d.providers[role].Claims[k] = v
		}
	}
	return w
}

// begin starts the context of the walk, which bounds the processes and
// every request to limit, and opens the browser of each person. The
// deadline counts from now, after the build of the commands (P7-05).
func (w *walk) begin(limit time.Duration) context.CancelFunc {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	w.ctx = ctx
	w.staff, w.citizen, w.checker, w.operator = newBrowser(ctx, w.t), newBrowser(ctx, w.t), newBrowser(ctx, w.t), newBrowser(ctx, w.t)
	return cancel
}

// start runs the processes and names the pairs.
func (w *walk) start() {
	w.d.start(w.ctx)
	for _, rp := range w.d.pairs {
		switch rp.pair.Role {
		case commonv1.Role_ROLE_ISSUER:
			w.issuer = rp
		case commonv1.Role_ROLE_HOLDER:
			w.holder = rp
		case commonv1.Role_ROLE_VERIFIER:
			w.verifier = rp
		case commonv1.Role_ROLE_ADMIN:
			w.admin = rp
		}
	}
}

// peerChecks calls an internal Connect service of a running adapter as
// a stranger would (ADR-075). A call with no identity gets
// unauthenticated. The wallet portal holds an identity of the
// deployment, but the adapter lists only the admin for its tenants, so
// the call gets permission_denied. A token for another server gets
// unauthenticated.
func (w *walk) peerChecks() {
	w.t.Helper()
	adapter := "dpg-adapter-" + cli.ShortName(w.issuer.pair.Dpg.String())
	base := "http://127.0.0.1:" + strconv.Itoa(w.issuer.ports[adapter])
	list := func(c *http.Client) connect.Code {
		_, err := backendv1connect.NewTenantBackendServiceClient(c, base).
			ListTenants(w.ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
		return connect.CodeOf(err)
	}
	if code := list(http.DefaultClient); code != connect.CodeUnauthenticated {
		w.t.Errorf("a call with no identity got %v, want unauthenticated", code)
	}
	values := w.holder.identities["wallet-portal"]
	wallet, err := peerauth.Load(func(k string) string { return values[k] })
	if err != nil {
		w.t.Fatal(err)
	}
	if code := list(wallet.Client(http.DefaultClient)); code != connect.CodePermissionDenied {
		w.t.Errorf("the wallet portal got %v from the tenant service, want permission_denied", code)
	}
	// A token names the host of its callee. A token that the wallet
	// portal signed for the adapter of its own pair opens no other
	// server, so a party that reads it on the network cannot replay it
	// at the adapter of the issuer pair.
	own := "127.0.0.1:" + strconv.Itoa(w.holder.ports[adapter])
	replay, err := wallet.Header("/vca.backend.v1.TenantBackendService/ListTenants", own)
	if err != nil {
		w.t.Fatal(err)
	}
	req := connect.NewRequest(&backendv1.ListTenantsRequest{})
	for k, v := range replay {
		req.Header()[k] = v
	}
	_, err = backendv1connect.NewTenantBackendServiceClient(http.DefaultClient, base).ListTenants(w.ctx, req)
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated {
		w.t.Errorf("a token for the adapter of the holder pair got %v at the issuer pair, want unauthenticated", code)
	}
}

// signIn opens the home of a pair and follows the sign in of its
// identity provider.
func (w *walk) signIn(b *browser, rp *runningPair) page {
	w.t.Helper()
	first := b.get(rp.public+"/").must(w.t).has(w.t, "Continue with")
	return b.get(first.link(w.t, "Sign in")).must(w.t)
}

// landing reads the landing: the stack runs, and every role is live.
func (w *walk) landing() {
	w.t.Helper()
	p := newBrowser(w.ctx, w.t).get(w.d.landing+"/").must(w.t).
		has(w.t, "One front door to open credential infrastructure.", w.stack)
	if !regexp.MustCompile(`Roles Issuer Live Holder Live Verifier Live Admin Live`).MatchString(text(p.body)) {
		w.t.Fatalf("the landing does not show every role live: %s", text(p.body))
	}
}

// publish uploads the schema and publishes it on the stack.
func (w *walk) publish() {
	w.t.Helper()
	schemas := w.staff.get(w.issuer.public + "/portal/").must(w.t)
	form := w.staff.get(schemas.link(w.t, "Publish schema")).must(w.t).form(w.t, "/portal/publish")
	w.staff.upload(form, "farmer-registration.json", farmerSchema, "type", "FarmerRegistration", "name", "Farmer registration").
		must(w.t).has(w.t, "The version is published. The DPG can issue it now.")
}

// issue walks the issue wizard for one farmer and returns the offer and
// the transaction code the result page shows. The delivery changes pick
// another channel than the first one.
func (w *walk) issue(delivery ...string) (string, string) {
	w.t.Helper()
	b := w.staff
	start := b.get(w.issuer.public + "/issue/").must(w.t)
	source := b.submit(start.form(w.t, "/issue/source")).must(w.t)
	claims := b.submit(source.form(w.t, "/issue/source"), "source", "single").must(w.t)
	deliveryPage := b.submit(claims.form(w.t, "/issue/delivery"),
		"claim.fullName", "Wanjiku Njeri", "claim.farmerID", "FM-0042", "claim.county", "Kiambu").must(w.t)
	review := b.submit(deliveryPage.form(w.t, "/issue/review"), delivery...).must(w.t).has(w.t, w.stack)
	result := b.submit(review.form(w.t, "/issue/offers")).must(w.t).has(w.t, "Credential offer ready")
	offer := html.UnescapeString(regexp.MustCompile(`openid-credential-offer://[^"<\s]+`).FindString(result.body))
	pin := ""
	if m := regexp.MustCompile(`Transaction code[^0-9]*([0-9]{4,8})`).FindStringSubmatch(text(result.body)); m != nil {
		pin = m[1]
	}
	return offer, pin
}

// claimInBrowser signs the farmer in to the wallet and claims the offer
// into the browser store, as wallet.js does (ADR-073). The portal trades
// the code, the browser signs the proof with its key, and the issuer
// binds the credential to that key. The card names the trust of the
// issuer. It returns the credential.
func (w *walk) claimInBrowser(offer, pin, trust string) string {
	w.t.Helper()
	w.signIn(w.citizen, w.holder).has(w.t, "Your browser keeps these credentials.")
	paste := w.citizen.get(w.holder.public+"/wallet/claim").must(w.t).form(w.t, "/wallet/claim/offer")
	keys := w.citizen.get(w.holder.public+"/wallet/keys").must(w.t).has(w.t, "Your browser makes its key at your first claim")
	if strings.Contains(keys.body, "did not answer") {
		w.t.Fatalf("the keys page of the browser store asked the wallet of the stack:\n%s", text(keys.body))
	}
	offerPage := w.citizen.submit(paste, "offer", offer).must(w.t).has(w.t, "data-browser-claim", `data-holder-key="register"`)
	accept := offerPage.form(w.t, "/wallet/accept")
	if pin != "" {
		accept.values.Set("pin", pin)
	}
	step := w.citizen.script(accept, "/wallet/claim/proof", "jwk", w.key.jwk)
	done := w.citizen.script(accept, "/wallet/claim/finish",
		"claim", step["claim"], "signature", w.key.sign(w.t, step["signing_input"]))
	// The browser made its key for the claim, so wallet.js binds it to
	// the wallet once (ADR-020 decision 4). The keys page then names it.
	proof := w.citizen.script(accept, "/wallet/holder-key/proof")
	bound := w.citizen.script(accept, "/wallet/holder-key", "jwk", w.key.jwk, "signature", w.key.sign(w.t, proof["signing_input"]))
	if bound["thumbprint"] == "" || !strings.HasPrefix(bound["holder_did"], "did:jwk:") {
		w.t.Fatalf("the binding answered %v", bound)
	}
	w.citizen.get(w.holder.public+"/wallet/keys").must(w.t).has(w.t, "Your browser holds a key for this wallet.", bound["thumbprint"])
	w.citizen.get(w.holder.public+"/wallet/").must(w.t).has(w.t, "Farmer registration", "Wanjiku Njeri", trust)
	return done["credential"]
}

// claimWithSignIn claims an offer of the authorization code grant into
// the browser store (ADR-082). The offer page asks the farmer to sign in
// at the issuer. The wallet pushes the authorization request with PKCE,
// the authorization server of the issuer sends the browser back to the
// wallet with a code, and the wallet trades it. The browser then signs
// the proof with its key. It returns the credential.
func (w *walk) claimWithSignIn(offer string) string {
	w.t.Helper()
	paste := w.citizen.get(w.holder.public+"/wallet/claim").must(w.t).form(w.t, "/wallet/claim/offer")
	offerPage := w.citizen.submit(paste, "offer", offer).must(w.t).
		has(w.t, "The issuer asks you to sign in first.", "Offered by", "Sign in at issuer")
	if strings.Contains(offerPage.body, "data-browser-claim") {
		w.t.Fatal("an offer of the authorization code grant asks the browser to claim before the sign in")
	}
	authorized := w.citizen.submit(offerPage.form(w.t, "/wallet/claim")).must(w.t).has(w.t, "data-browser-claim")
	if authorized.url.Path != "/wallet/claim/callback" {
		w.t.Fatalf("the sign in ended at %s, want the callback of the wallet", authorized.url)
	}
	accept := authorized.form(w.t, "/wallet/accept")
	step := w.citizen.script(accept, "/wallet/claim/proof", "jwk", w.key.jwk)
	done := w.citizen.script(accept, "/wallet/claim/finish",
		"claim", step["claim"], "signature", w.key.sign(w.t, step["signing_input"]))
	if done["credential"] == "" {
		w.t.Fatalf("the claim after the sign in answered %v", done)
	}
	return done["credential"]
}

// check pastes the credential into the public check page of the
// verifier and returns the verdict page.
func (w *walk) check(credential string) page {
	w.t.Helper()
	b := newBrowser(w.ctx, w.t)
	form := b.get(w.verifier.public+"/verify/").must(w.t).form(w.t, "/verify/")
	return b.submit(form, "presentation", credential).must(w.t)
}

// adminSignIn binds the first admin with the bootstrap token.
func (w *walk) adminSignIn() page {
	w.t.Helper()
	first := w.operator.get(w.admin.public + "/").must(w.t)
	return w.operator.submit(first.form(w.t, "/auth/login"), "bootstrap_token", w.admin.env["VCA_SECRETS_BOOTSTRAP_TOKEN"]).
		must(w.t).has(w.t, "Add at least one issuer to the trust list.")
}

// query crawls the trusted issuers and saves a DCQL query for the
// credential, with the trusted issuer and the status rules.
func (w *walk) query() {
	w.t.Helper()
	b := w.checker
	discover := b.get(w.verifier.public + "/discovery/").must(w.t)
	b.submit(discover.form(w.t, "/discovery/crawl")).must(w.t).has(w.t, "Trusted issuers, 1 found", "The crawl finished.")
	builder := b.get(w.verifier.public + "/discovery/dcql/").must(w.t)
	pick := builder.option(w.t, "pick", "Farmer registration")
	builder = b.submit(builder.form(w.t, "/discovery/dcql/"), "pick", pick, "action", "preview").must(w.t)
	form := builder.form(w.t, "/discovery/dcql/")
	form.values["claim"] = []string{"fullName", "farmerID"}
	form.values["trust"] = []string{"issuer", "status"}
	b.submit(form, "display_name", "Farmer registration check",
		"purpose", "Confirm the farmer registration before the subsidy payment.", "action", "save").
		must(w.t).has(w.t, "The template is saved.")
}

// request sends the query through the VCA verifier as a link, the
// farmer answers it from the wallet, and the verifier reads the state.
func (w *walk) request() page {
	w.t.Helper()
	form := w.checker.get(w.verifier.public+"/scan/requests/new").must(w.t).form(w.t, "/scan/requests/")
	sent := w.checker.submit(form, "through", "vca", "deliver", "link").must(w.t).has(w.t, "No wallet has answered yet.")
	link := html.UnescapeString(regexp.MustCompile(`openid4vp://[^"<\s]+`).FindString(sent.body))
	paste := w.citizen.get(w.holder.public+"/wallet/claim").must(w.t).form(w.t, "/wallet/claim/offer")
	consent := w.citizen.submit(paste, "offer", link).must(w.t).has(w.t, "Matched credential", "Farmer registration")
	// The credential is bound to the key of the browser, so wallet.js
	// signs the key binding of the answer first (ADR-073).
	answer := consent.has(w.t, "data-key-binding").form(w.t, "/wallet/present")
	input := w.citizen.script(answer, "/wallet/present/binding")["signing_input"]
	if input == "" {
		w.t.Fatal("the wallet asks for no key binding of a bound credential")
	}
	w.citizen.submit(answer, "key_binding", input+"."+w.key.sign(w.t, input)).must(w.t).has(w.t, "The verifier has your answer.")
	return w.checker.get(sent.url.String()).must(w.t)
}

// done checks the time budget and counts the pages that passed the
// accessibility rules.
func (w *walk) done(began time.Time) {
	w.t.Helper()
	pages := 0
	for _, b := range []*browser{w.staff, w.citizen, w.checker, w.operator} {
		pages += b.pages
	}
	if took := time.Since(began); took > budget {
		w.t.Errorf("the walkthrough took %s, more than %s", took, budget)
	}
	w.t.Logf("%d pages passed the accessibility rules", pages)
}

// TestWalkthroughWaltid walks a walt.id deployment: the landing, the
// sign in of each role with the identity provider, a credential issued
// on the walt.id fixtures, the claim into the browser store of the
// wallet, a check, the trust decision of the admin, and a request and
// its answer. The verdict turns from "issuer untrusted" to valid. Every
// page passes the accessibility rules of the kit.
func TestWalkthroughWaltid(t *testing.T) {
	api := newWaltidIssuer(t)
	w := newWalk(t, configv1.Dpg_DPG_WALTID, "walt.id Community Stack", map[string]string{"http://waltid-issuer-api:7002": api.srv.URL})
	// The budget starts once the commands are built: a first run on a
	// machine builds them once.
	defer w.begin(2 * budget)()
	began := time.Now()
	w.start()
	w.landing()
	w.peerChecks()

	// The issuer staff signs in, makes the identity of the issuer, and
	// asks for an entry in the trust list.
	overview := w.signIn(w.staff, w.issuer).has(t, "Your issuer on walt.id Community Stack.", "Amina Odhiambo")
	identity := w.staff.get(overview.link(t, "Set up the identity")).must(t)
	identity = w.staff.submit(identity.form(t, "/identity/provision"), "method", "did:key", "key_type", "Ed25519").must(t)
	identity.has(t, "The trust registry holds a pending entry for did:key:")
	w.publish()
	offer, pin := w.issue()

	// The farmer claims the offer into the browser store of the wallet.
	// The browser signs the proof with its own key (ADR-073).
	credential := w.claimInBrowser(offer, pin, "No trust list names")

	// The verifier checks the credential. No trust list names the issuer.
	w.signIn(w.checker, w.verifier).has(t, "Queries you saved, requests in flight and recent results.", "Otieno Kamau")
	w.check(credential).has(t, "Verdict Not valid", "issuer untrusted", "the issuer is not on an enabled trust list")

	// The admin approves the entry that the issuer asked for.
	trust := w.operator.get(w.adminSignIn().link(t, "Trust")).must(t).has(t, "1 pending review")
	w.operator.submit(trust.form(t, "/admin/trust/approve")).must(t).has(t, "The entry is active.")

	// The verifier asks the farmer for the credential. The wallet signs
	// the key binding of the answer, and the verdict is valid. The check
	// of the same credential turns to issuer trusted too.
	w.query()
	w.request().has(t, "Verified at", "Valid", "the issuer is on an enabled trust list",
		"the issuer did not set the status of the credential")
	// A pasted credential carries no key binding, so the check page
	// names the trusted issuer and the missing binding. The answer of
	// the wallet above holds the binding and reads valid.
	w.check(credential).has(t, "issuer trusted", "the presentation carries no key binding JWT")
	w.citizen.get(w.holder.public+"/wallet/").must(t).has(t, "Issuer: trusted")

	// The issuer offers the credential with the authorization code
	// grant. The farmer signs in at the issuer, and the browser claims
	// with its own key (ADR-082).
	signedOffer, _ := w.issue("channel", "CHANNEL_OID4VCI_AUTHCODE", "binding_token", "sub", "binding_subject", "farmerID")
	signed := w.claimWithSignIn(signedOffer)
	w.check(signed).has(t, "issuer trusted")
	if api.onboarded != 1 {
		t.Errorf("the issuer API onboarded %d keys, want 1", api.onboarded)
	}
	w.done(began)
}

// TestWalkthroughCredebl walks a CREDEBL deployment through the test
// double of the platform. The operator made the DID of the
// organisation in the platform, so the identity page shows it at once.
// The admin adds that DID to the trust list. The offer of the platform
// is revocable, and the revocation of the issuer turns the verdict to
// invalid (P6-C1b, P6-C5b).
func TestWalkthroughCredebl(t *testing.T) {
	stack := newCredeblStack(t)
	w := newWalk(t, configv1.Dpg_DPG_CREDEBL, "CREDEBL", map[string]string{
		"http://credebl-api-gateway:5000": stack.srv.URL, "http://credebl-agent.vca.internal:8001": stack.srv.URL,
	})
	defer w.begin(2 * budget)()
	began := time.Now()
	// The operator answers the two questions of vca setup for CREDEBL.
	// vca dpg bootstrap then writes the organisation and its OID4VC
	// issuer into the .env of each CREDEBL pair.
	w.d.answers[cli.PlatformAdminEmailSetting] = "platform.admin@agriculture.example"
	w.d.answers[cli.CredeblLedgersSetting] = "bcovrin:testnet"
	for _, name := range []string{"issuer-credebl", "holder-credebl", "verifier-credebl"} {
		w.d.set(name, "VCA_CREDEBL_ORG_ID", stack.org)
		w.d.set(name, "VCA_CREDEBL_ISSUER_ID", stack.issuer)
	}
	w.start()
	w.landing()

	// The operator made the DID of the organisation in the platform, so
	// the identity is there when the staff signs in.
	overview := w.signIn(w.staff, w.issuer).has(t, "Your issuer on CREDEBL.", "Amina Odhiambo")
	w.staff.get(overview.link(t, "Identity")).must(t).
		has(t, stack.did, "Ministry of Agriculture", "DIDs from the operator", "PKI (X.509)")
	w.publish()
	offer, pin := w.issue()
	if pin == "" {
		t.Fatal("the result page shows no transaction code")
	}
	credential := w.claimInBrowser(offer, pin, "No trust list names")
	w.signIn(w.checker, w.verifier).has(t, "Otieno Kamau")
	w.check(credential).has(t, "Verdict Not valid", "issuer untrusted")

	// The admin adds the DID of the organisation to the trust list.
	trust := w.operator.get(w.adminSignIn().link(t, "Trust")).must(t)
	trust = w.operator.submit(trust.form(t, "/admin/trust"), "identifier", stack.did, "display_name", "Ministry of Agriculture",
		"role", "issuer", "status", "active", "service_endpoint", w.issuer.public).must(t)
	trust.has(t, "The registry saved the entry and publishes the lists again.")

	w.query()
	w.request().has(t, "Verified at", "Valid", "the issuer is on an enabled trust list",
		"the issuer did not set the status of the credential")
	// A pasted credential carries no key binding, so the check page
	// names the trusted issuer and the missing binding. The answer of
	// the wallet above holds the binding and reads valid.
	w.check(credential).has(t, "issuer trusted", "the presentation carries no key binding JWT")

	// The credential carries an entry of the status list of the stack,
	// and the record of the offer names that entry. The issuer revokes
	// the record, and the agent sets the bit in the list of the stack.
	// A sync from the ledger adds no second record of the credential.
	// The verifier syncs its cache, and the check turns to invalid.
	issued := w.staff.get(w.issuer.public+"/issued/").must(t).has(t, "1 of 1 credentials")
	own := regexp.MustCompile(`href="(/issued/[0-9a-f]{32})"`).FindStringSubmatch(issued.body)
	if own == nil {
		t.Fatalf("the issued page links no record: %s", text(issued.body))
	}
	sync := w.staff.get(issued.link(t, "Sync from stack")).must(t).has(t, "CREDEBL keeps a ledger of the credentials it issued.")
	w.staff.submit(sync.form(t, "/issued/sync"),
		"type", "FarmerRegistration_dc+sd-jwt", "attribute", "farmerID", "value", "FM-0042").
		must(t).has(t, "The log added 0 of 1 credentials.")
	record := w.staff.get(w.issuer.public+own[1]).must(t).
		has(t, "Issuing adapter dpg-adapter-credebl", "index 4211", "The status list of CREDEBL.")
	dialog := w.staff.get(record.link(t, "Revoke")).must(t)
	w.staff.submit(dialog.form(t, "/revoke"), "reason", "The farm registration ended.").
		must(t).has(t, "You revoked the credential.", "The stack made the change.")
	cache := w.checker.get(w.verifier.public + "/portal/cache/").must(t)
	w.checker.submit(cache.form(t, "/portal/cache/sync")).must(t).has(t, "The cache read every source.")
	w.check(credential).has(t, "Verdict Not valid", "the issuer set the status of the credential")
	if len(stack.unknown) != 0 {
		t.Errorf("the adapter called paths the stack double does not serve: %v", stack.unknown)
	}
	w.done(began)
}
