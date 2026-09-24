// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// dpgs lists every DPG of the enum in number order. The tests never name
// a vendor, so the enum is the only source.
func dpgs() []configv1.Dpg {
	var out []configv1.Dpg
	for number := range configv1.Dpg_name {
		if number != 0 {
			out = append(out, configv1.Dpg(number))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// roles lists the four roles in the order of the pages.
func roles() []commonv1.Role {
	return []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER, commonv1.Role_ROLE_ADMIN}
}

// stackNames are the display names the fake adapters report, by DPG.
var stackNames = map[configv1.Dpg]string{}

func init() {
	for i, d := range dpgs() {
		stackNames[d] = []string{"Alpha Stack", "Beta Stack", "Gamma Stack"}[i]
	}
}

// capabilities is the answer of the fake adapter of one pair.
func capabilities(role commonv1.Role, d configv1.Dpg) *backendv1.GetCapabilitiesResponse {
	name := stackNames[d]
	resp := &backendv1.GetCapabilitiesResponse{
		Roles:     []commonv1.Role{role},
		Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VCI, backendv1.Protocol_PROTOCOL_OID4VP_PEX},
		Channels:  []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
		DpgInfo: &backendv1.DpgInfo{
			DisplayName: name, Version: "1.2.3",
			Components: []*backendv1.Component{
				{Name: "issuer-api", Version: "1.2.3", RepositoryUrl: "https://example.org/" + strings.ToLower(strings.Fields(name)[0]) + "/repo", DocsUrl: "https://docs.example.org/" + strings.ToLower(strings.Fields(name)[0]), License: "Apache-2.0"},
				{Name: "keycloak", Version: "25.0", RepositoryUrl: "https://example.org/keycloak", DocsUrl: "https://docs.example.org/keycloak"},
			},
		},
	}
	if d == dpgs()[1] {
		resp.Protocols = append(resp.Protocols, backendv1.Protocol_PROTOCOL_OID4VP_DCQL)
		resp.Features = append(resp.Features, backendv1.Feature_FEATURE_MULTI_TENANCY)
	}
	return resp
}

// peer builds the candidate of one pair.
func peer(role commonv1.Role, d configv1.Dpg) topology.Peer {
	name := topology.PairName(role, d)
	services := map[string]string{topology.HomeService(role): "http://" + name + "-home:8080"}
	if role != commonv1.Role_ROLE_ADMIN {
		services[topology.AdapterService(d)] = "http://" + name + "-adapter:8090"
	}
	if auth := topology.AuthService(role); auth != "" {
		services[auth] = "http://" + name + "-auth:8081"
	}
	return topology.Peer{Pair: name, Role: role, Dpg: d, PublicURL: "https://" + name + ".labs.example", Services: services}
}

// fakeSource answers with a fixed snapshot.
type fakeSource struct {
	snap topology.Snapshot
}

func (f fakeSource) Snapshot(context.Context) topology.Snapshot { return f.snap }

// snapshot builds a snapshot from a state function.
func snapshot(state func(role commonv1.Role, d configv1.Dpg) topology.State) topology.Snapshot {
	snap := topology.Snapshot{Taken: time.Date(2026, 9, 24, 9, 41, 0, 0, time.UTC)}
	for _, role := range roles() {
		for _, d := range dpgs() {
			st := topology.Status{Peer: peer(role, d), State: state(role, d)}
			if st.State == topology.Live && role != commonv1.Role_ROLE_ADMIN {
				st.Capabilities = capabilities(role, d)
			}
			snap.Peers = append(snap.Peers, st)
		}
	}
	return snap
}

func allLive(commonv1.Role, configv1.Dpg) topology.State { return topology.Live }

func newPages(t *testing.T, snap topology.Snapshot) http.Handler {
	t.Helper()
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	p, err := pages.New(pages.Options{
		Kit: kit, Source: fakeSource{snap: snap}, Version: "0.9.0", PublicURL: "https://vca.labs.example",
		RepositoryURL: "https://example.org/vca", DocsURL: "https://example.org/vca/docs",
		Now: func() time.Time { return time.Date(2026, 9, 24, 9, 42, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux
}

func get(t *testing.T, h http.Handler, path string, htmx bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLandingAllStacks(t *testing.T) {
	h := newPages(t, snapshot(allLive))
	rec := get(t, h, "/", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<title>Verifiable Credentials Adapter</title>`,
		`<h1>One front door to open credential infrastructure.</h1>`,
		`<a href="#how">How it works</a>`, `<a href="#stacks">Stacks</a>`,
		`<a href="https://example.org/vca/docs" rel="noopener">Docs</a>`, `<a href="https://example.org/vca" rel="noopener">GitHub</a>`,
		`<a href="/roles/" hx-get="/roles/"`, `<a class="btn btn-primary" href="/roles/">Start with VCA</a>`,
		`<a class="btn btn-ghost" href="#how">New to credentials? Read the primer.</a>`,
		`<section class="block" id="how"`, `<h2 id="how-title">Three ideas, two minutes.</h2>`, `<ul class="tiles tiles-3">`,
		`href="https://digitalpublicgoods.net/standard/" rel="noopener"`, `href="https://www.w3.org/TR/vc-data-model-2.0/" rel="noopener"`,
		`<figure class="figure" id="triangle">`, `role="img"`, `<title id="triangle-title">The triangle of trust</title>`,
		`<figcaption id="triangle-caption" class="visually-hidden">Issuer, holder and verifier, with the trust registry between them.</figcaption>`,
		`>Issuer</text>`, `>Holder</text>`, `>Verifier</text>`, `>Trust registry</text>`,
		`<section class="block" id="stacks" aria-labelledby="stacks-title" hx-get="/stacks" hx-swap="outerHTML" hx-trigger="every 30s">`,
		`<h2 id="stacks-title">Stacks on this deployment</h2>`, `<span class="block-meta">VCA 0.9.0, updated 09:42 UTC</span>`,
		`<h3 id="stack-`, `Alpha Stack</h3>`, `Beta Stack</h3>`, `Gamma Stack</h3>`, `<span class="stack-version">Pinned 1.2.3</span>`,
		`<span class="stack-component-name">issuer-api</span><span class="stack-component-version">pinned 1.2.3</span>`,
		`<a href="https://example.org/alpha/repo" rel="noopener">GitHub</a>`, `<a href="https://docs.example.org/alpha" rel="noopener">Documentation</a>`,
		`<span class="stack-component-name">keycloak</span><span class="stack-component-version">pinned 25.0</span>`,
		`<li class="stack-role stack-role-live"><span>Issuer</span><span class="badge badge-ok">Live</span></li>`,
		`<li class="stack-role stack-role-live"><span>Admin</span><span class="badge badge-ok">Live</span></li>`,
		`<section class="cta" id="start"`, `<h2 id="start-title">Pick a role. Walk one flow end to end.</h2>`,
		`<span class="ft-note">Centre for Digital Public Infrastructure, Apache-2.0.</span>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("landing missing %q", want)
		}
	}
	if n := strings.Count(doc, `<article class="stack"`); n != 3 {
		t.Errorf("got %d stack cards, want 3", n)
	}
	if n := strings.Count(doc, `<li class="stack-role`); n != 12 {
		t.Errorf("got %d role rows, want 12", n)
	}
	if strings.Contains(doc, "Starting") || strings.Contains(doc, "ZgotmplZ") {
		t.Error("every pair is live, and no value was escaped as unsafe")
	}
	// The stack repository links come from the adapters, one per component.
	if n := strings.Count(doc, `rel="noopener">GitHub</a>`); n != 7 {
		t.Errorf("got %d GitHub links, want one in the nav and six on the cards", n)
	}
	if t.Failed() {
		t.Log(doc)
	}
}

func TestLandingOneRole(t *testing.T) {
	first := dpgs()[0]
	snap := snapshot(func(role commonv1.Role, d configv1.Dpg) topology.State {
		if role == commonv1.Role_ROLE_ISSUER && d == first {
			return topology.Live
		}
		return topology.Absent
	})
	doc := get(t, newPages(t, snap), "/", false).Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<a class="btn btn-primary" href="/roles/issuer/">Continue as issuer</a>`,
		`<div class="ethos note">`, `This deployment runs the issuer role on Alpha Stack. Other roles appear when an admin deploys them.`,
		`<h2 id="start-title">One role is live. Start there.</h2>`, `The role picker steps aside when one role runs.`,
		`Alpha Stack</h3>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("one role landing missing %q", want)
		}
	}
	for _, absent := range []string{"Beta Stack", "Gamma Stack", "Start with VCA", `href="/roles/">`, ">Holder</span>", ">Verifier</span>", ">Admin</span>"} {
		if strings.Contains(doc, absent) {
			t.Errorf("one role landing shows %q, which does not run", absent)
		}
	}
	if n := strings.Count(doc, `<article class="stack"`); n != 1 {
		t.Errorf("got %d stack cards, want 1", n)
	}
	if t.Failed() {
		t.Log(doc)
	}
}

func TestLandingHidesAbsentAndMarksStarting(t *testing.T) {
	first, second := dpgs()[0], dpgs()[1]
	snap := snapshot(func(role commonv1.Role, d configv1.Dpg) topology.State {
		switch {
		case d == first:
			return topology.Live
		case d == second && role == commonv1.Role_ROLE_VERIFIER:
			return topology.Starting
		case d == second && role == commonv1.Role_ROLE_ISSUER:
			return topology.Live
		default:
			return topology.Absent
		}
	})
	doc := get(t, newPages(t, snap), "/", false).Body.String()
	a11ytest.AssertPage(t, doc)
	if n := strings.Count(doc, `<article class="stack"`); n != 2 {
		t.Errorf("got %d stack cards, want 2", n)
	}
	if strings.Contains(doc, "Gamma Stack") {
		t.Error("an absent stack shows")
	}
	if !strings.Contains(doc, `<li class="stack-role stack-role-starting"><span>Verifier</span><span class="badge badge-warn">Starting</span></li>`) {
		t.Error("a starting pair shows the word Starting")
	}
	// The second stack has two present roles: one live, one starting.
	beta := doc[strings.Index(doc, "Beta Stack</h3>"):]
	beta = beta[:strings.Index(beta, "</article>")]
	if strings.Count(beta, `<li class="stack-role`) != 2 || strings.Contains(beta, ">Holder</span>") {
		t.Errorf("beta rows:\n%s", beta)
	}
	// Several live roles keep the picker as the way in.
	if !strings.Contains(doc, `href="/roles/">Start with VCA</a>`) {
		t.Error("the CTA goes to the role picker")
	}
}

func TestLandingNoLiveRole(t *testing.T) {
	doc := get(t, newPages(t, snapshot(func(commonv1.Role, configv1.Dpg) topology.State { return topology.Absent })), "/", false).Body.String()
	a11ytest.AssertPage(t, doc)
	if strings.Contains(doc, "btn-primary") || strings.Contains(doc, `class="cta"`) || strings.Contains(doc, `<article class="stack"`) {
		t.Error("a deployment with no live role has no call to action and no stack card")
	}
	if n := strings.Count(doc, "No stack runs yet. Start a pair with the vca command, then reload this page."); n < 1 {
		t.Error("the page says that no stack runs")
	}
	// A starting pair alone is not live: it shows on its card, with no CTA.
	first := dpgs()[0]
	starting := snapshot(func(role commonv1.Role, d configv1.Dpg) topology.State {
		if d == first && role == commonv1.Role_ROLE_HOLDER {
			return topology.Starting
		}
		return topology.Absent
	})
	doc = get(t, newPages(t, starting), "/", false).Body.String()
	a11ytest.AssertPage(t, doc)
	if strings.Contains(doc, "btn-primary") || !strings.Contains(doc, "Starting") {
		t.Errorf("a starting pair shows as starting with no call to action:\n%s", doc)
	}
	// With no capabilities yet the card names the stack by its id.
	if !strings.Contains(doc, `<h3 id="stack-`) || strings.Contains(doc, "Alpha Stack") {
		t.Error("a starting stack has no display name yet")
	}
}

func TestStacksFragmentForHTMX(t *testing.T) {
	h := newPages(t, snapshot(allLive))
	rec := get(t, h, "/stacks", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	doc := rec.Body.String()
	a11ytest.AssertFragment(t, doc)
	if strings.Contains(doc, "<html") || strings.Contains(doc, "<h1") {
		t.Error("the fragment is not a full page")
	}
	for _, want := range []string{
		`<section class="block" id="stacks" aria-labelledby="stacks-title" hx-get="/stacks" hx-swap="outerHTML" hx-trigger="every 30s">`,
		`<ul class="stacks">`, `Alpha Stack</h3>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("fragment missing %q\n%s", want, doc)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	// A plain request gets the same fragment.
	if plain := get(t, h, "/stacks", false).Body.String(); plain != doc {
		t.Error("the fragment differs between htmx and plain requests")
	}
}

func TestDescriptorJSON(t *testing.T) {
	first := dpgs()[0]
	snap := snapshot(func(role commonv1.Role, d configv1.Dpg) topology.State {
		switch {
		case d == first && role == commonv1.Role_ROLE_ISSUER:
			return topology.Live
		case d == first && role == commonv1.Role_ROLE_HOLDER:
			return topology.Starting
		default:
			return topology.Absent
		}
	})
	rec := get(t, newPages(t, snap), "/.well-known/vca.json", false)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, type = %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var got struct {
		Version   string `json:"version"`
		PublicURL string `json:"public_url"`
		Taken     string `json:"taken"`
		Stacks    []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Version    string `json:"version"`
			Components []struct {
				Name          string `json:"name"`
				Version       string `json:"version"`
				RepositoryURL string `json:"repository_url"`
				DocsURL       string `json:"docs_url"`
			} `json:"components"`
		} `json:"stacks"`
		Pairs []struct {
			Pair      string `json:"pair"`
			Role      string `json:"role"`
			Stack     string `json:"stack"`
			State     string `json:"state"`
			PublicURL string `json:"public_url"`
		} `json:"pairs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, rec.Body.String())
	}
	if got.Version != "0.9.0" || got.PublicURL != "https://vca.labs.example" || got.Taken != "2026-09-24T09:41:00Z" {
		t.Errorf("head = %+v", got)
	}
	if len(got.Stacks) != 1 || got.Stacks[0].Name != "Alpha Stack" || got.Stacks[0].Version != "1.2.3" || len(got.Stacks[0].Components) != 2 {
		t.Errorf("stacks = %+v", got.Stacks)
	}
	if len(got.Pairs) != 2 || got.Pairs[0].Role != "issuer" || got.Pairs[0].State != "live" || got.Pairs[1].Role != "holder" || got.Pairs[1].State != "starting" {
		t.Errorf("pairs = %+v", got.Pairs)
	}
	if got.Pairs[0].Pair != topology.PairName(commonv1.Role_ROLE_ISSUER, first) || got.Pairs[0].Stack != got.Stacks[0].ID || got.Pairs[0].PublicURL == "" {
		t.Errorf("pair = %+v", got.Pairs[0])
	}
	if !strings.Contains(rec.Body.String(), `"repository_url"`) || strings.Contains(rec.Body.String(), "absent") {
		t.Errorf("body:\n%s", rec.Body.String())
	}
}

func TestNotFoundPage(t *testing.T) {
	h := newPages(t, snapshot(allLive))
	rec := get(t, h, "/nothing-here", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	if !strings.Contains(rec.Body.String(), "This page does not exist.") {
		t.Errorf("body:\n%s", rec.Body.String())
	}
	if rec = get(t, h, "/", true); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "<html") || rec.Header().Get("HX-Title") == "" {
		t.Error("an htmx request for the landing gets the partial with a title")
	}
}

// TestNoVendorNameInLandingSource keeps ADR-001 decision 4: the landing
// learns every DPG name from the adapters, never from a literal.
func TestNoVendorNameInLandingSource(t *testing.T) {
	// The pattern is built from parts, so this file passes its own check.
	vendor := regexp.MustCompile("(?i)" + strings.Join([]string{"wal" + "t", "in" + "ji", "cre" + "debl"}, "|"))
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".svg") && !strings.HasSuffix(path, ".md") {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a path under the service
		if err != nil {
			return err
		}
		if m := vendor.Find(data); m != nil {
			t.Errorf("%s names a vendor: %q", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsMissingParts(t *testing.T) {
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pages.New(pages.Options{Source: fakeSource{}}); err == nil {
		t.Error("no kit passed")
	}
	if _, err := pages.New(pages.Options{Kit: kit}); err == nil {
		t.Error("no source passed")
	}
}

// failingKit fails on one component name and passes the rest through.
type failingKit struct {
	kit  *components.Kit
	name string
}

func (f failingKit) HTML(name string, data any) (template.HTML, error) {
	if name == f.name {
		return "", errors.New("boom")
	}
	return f.kit.HTML(name, data)
}

func (f failingKit) RenderPage(w http.ResponseWriter, r *http.Request, page components.Page) error {
	if f.name == "page" {
		return errors.New("boom")
	}
	return f.kit.RenderPage(w, r, page)
}

// TestRenderFailuresAnswer500 drives every render error path: each
// component of each page can fail, and the answer is a 500 with the
// catalogue sentence, never a half page.
func TestRenderFailuresAnswer500(t *testing.T) {
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, component string
	}{
		{"/", "figure"}, {"/", "tiles"}, {"/", "block"}, {"/", "stacks"}, {"/", "cta"}, {"/", "page"},
		{"/stacks", "block"}, {"/nothing", "empty"}, {"/nothing", "page"},
	} {
		p, newErr := pages.New(pages.Options{Kit: failingKit{kit: kit, name: tc.component}, Source: fakeSource{snap: snapshot(allLive)}})
		if newErr != nil {
			t.Fatal(newErr)
		}
		mux := http.NewServeMux()
		p.Register(mux)
		rec := get(t, mux, tc.path, false)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "The page did not render.") {
			t.Errorf("%s with a failing %s: status %d, body %q", tc.path, tc.component, rec.Code, rec.Body.String())
		}
	}
	// The one role landing renders the note; a failing note fails it.
	first := dpgs()[0]
	one := snapshot(func(role commonv1.Role, d configv1.Dpg) topology.State {
		if role == commonv1.Role_ROLE_ISSUER && d == first {
			return topology.Live
		}
		return topology.Absent
	})
	p, err := pages.New(pages.Options{Kit: failingKit{kit: kit, name: "note"}, Source: fakeSource{snap: one}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	if rec := get(t, mux, "/", false); rec.Code != http.StatusInternalServerError {
		t.Errorf("one role landing with a failing note: status %d", rec.Code)
	}
}
