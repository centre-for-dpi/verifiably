// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// auditDay is the day of the fixture events.
var auditDay = time.Date(2026, 3, 2, 7, 0, 0, 0, time.UTC)

// fixture is one event of a peer store at a minute of auditDay.
type fixture struct {
	minute int
	entry  auditlog.Entry
}

// peerStores holds the audit stores of the peers by pair/service.
type peerStores map[string]*auditlog.Log

// auditStore serves one real audit store of a peer behind the check of
// the admin session: the key set of this admin service at /.well-known.
// A down store answers every call with Unavailable.
func auditStore(t *testing.T, h *harness, service string, down bool, events ...fixture) (string, *auditlog.Log) {
	t.Helper()
	i := 0
	l, err := auditlog.New(store.Memory(), func() time.Time {
		at := auditDay
		if i < len(events) {
			at = auditDay.Add(time.Duration(events[i].minute) * time.Minute)
		}
		i++
		return at
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if _, aerr := l.Append(context.Background(), e.entry); aerr != nil {
			t.Fatal(aerr)
		}
	}
	authorize := oidcflow.AuditAuthorizer("", h.server.URL+"/.well-known/jwks.json", oidcflow.NewCache(h.server.Client(), 0))
	if down {
		authorize = func(context.Context, http.Header) error {
			return connect.NewError(connect.CodeUnavailable, errors.New("the store is down"))
		}
	}
	mux := http.NewServeMux()
	path, handler := auditlog.NewHandler(auditlog.Handler{Log: l, Service: service, Authorize: authorize})
	mux.Handle(path, handler)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { mustWrite(t, w, []byte("ready")) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, l
}

// auditPeers is a deployment with this admin pair and its trust
// registry, a live issuer pair on walt.id, a live verifier pair on Inji
// whose results store does not answer, and a live holder pair on
// CREDEBL. The stores hold events of one morning.
func auditPeers(stores peerStores) func(*testing.T, *harness) func(*config.Config, *app.Deps) {
	return func(t *testing.T, h *harness) func(*config.Config, *app.Deps) {
		t.Helper()
		ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mustWrite(t, w, []byte("ready"))
		}))
		t.Cleanup(ready.Close)
		add := func(key string, down bool, events ...fixture) string {
			u, l := auditStore(t, h, key[strings.Index(key, "/")+1:], down, events...)
			stores[key] = l
			return u
		}
		waltid := newFakeStack("walt.id Community Stack")
		waltid.version = "0.18.2"
		inji := newFakeStack("MOSIP Inji")
		inji.version = "0.14.0"
		credebl := newFakeStack("CREDEBL")
		ok := func(minute int, actor, action, target, detail string) fixture {
			return fixture{minute, auditlog.Entry{Actor: actor, Action: action, Target: target, Detail: detail, OK: true}}
		}
		bad := func(minute int, actor, action, target, detail string) fixture {
			return fixture{minute, auditlog.Entry{Actor: actor, Action: action, Target: target, Detail: detail}}
		}
		peers := []topology.Peer{
			{Pair: "admin-waltid", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: h.server.URL,
				Services: map[string]string{
					"admin": ready.URL,
					"trust-registry": add("admin-waltid/trust-registry", false,
						ok(12, "kc|root", "trust.UpsertEntry", "did:web:health.go.ke", msg.T("audit.trust.entry", "active"))),
				}},
			{Pair: "issuer-waltid", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: "https://issuer.vca.example",
				Services: map[string]string{
					"schema-registry": ready.URL, "dpg-adapter-waltid": waltid.serve(t),
					"issuer-auth": add("issuer-waltid/issuer-auth", false,
						ok(5, "kc|ada", "auth.Login", "keycloak", ""),
						bad(3, "", "auth.Login", "keycloak", msg.T("audit.reason.provider"))),
					"issuance": add("issuer-waltid/issuance", false,
						ok(20, "kc|ada", "issuance.Issue", "offer-7f3a", msg.T("audit.issuance.issue", "birth", "2", "oid4vci_preauth"))),
					"issued-credentials": add("issuer-waltid/issued-credentials", false,
						ok(31, "kc|ada", "issued.Revoke", "rec-19", msg.T("audit.issued.status", "revoked"))),
				}},
			{Pair: "verifier-inji", Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_INJI, PublicURL: "https://verifier.vca.example",
				Services: map[string]string{
					"dpg-adapter-inji":  inji.serve(t),
					"verifier-results":  add("verifier-inji/verifier-results", true),
					"verifier-auth":     add("verifier-inji/verifier-auth", false, ok(8, "kc|grace", "auth.Login", "esignet", "")),
					"verifier-policy":   ready.URL,
					"verifier-discover": ready.URL,
				}},
			{Pair: "holder-credebl", Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_CREDEBL, PublicURL: "https://holder.vca.example",
				Services: map[string]string{
					"wallet-portal": ready.URL, "dpg-adapter-credebl": credebl.serve(t),
					"wallet-auth": add("holder-credebl/wallet-auth", false, ok(15, "8d1f2c", "auth.Register", "national-id", "")),
				}},
		}
		return func(cfg *config.Config, deps *app.Deps) {
			cfg.Peers = peers
			deps.Prober = &topology.Prober{Peers: peers, Lookup: func(context.Context, string) ([]string, error) {
				return []string{"127.0.0.1"}, nil
			}}
		}
	}
}

// auditHarness signs in on a deployment with audit peers and writes one
// admin event of its own.
func auditHarness(t *testing.T) (*harness, peerStores) {
	t.Helper()
	stores := peerStores{}
	h := newHarnessWith(t, true, auditPeers(stores))
	h.signIn(t)
	return h, stores
}

// TestAuditPageMergesPeersInTimeOrder shows the events of this admin
// and of every live peer on one page, newest first, with the pair and
// the stack of each (ADR-039 decision 2).
func TestAuditPageMergesPeersInTimeOrder(t *testing.T) {
	h, _ := auditHarness(t)
	page := h.page(t, "/admin/audit")
	order := []string{
		"issued.Revoke", "issuance.Issue", "auth.Register", "trust.UpsertEntry", "auth.Login", "auth.Login",
	}
	at := 0
	for _, action := range order {
		i := strings.Index(page[at:], "<td>"+action)
		if i < 0 {
			t.Fatalf("the page misses %s after position %d", action, at)
		}
		at += i + 1
	}
	for _, want := range []string{
		"issuer-waltid", "walt.id Community Stack", "MOSIP Inji", "CREDEBL", "admin.Login",
		msg.T("audit.issued.status", "revoked"), msg.T("admin.audit.actor.none.label"),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page misses %q", want)
		}
	}
	// The admin sign in of this test is the newest event of all.
	if strings.Index(page, "<td>admin.Login") > strings.Index(page, "<td>issued.Revoke") {
		t.Error("the admin sign in does not come first")
	}
}

// TestAuditPeerDownIsNamed keeps the page when a peer store does not
// answer and names the pair and the service.
func TestAuditPeerDownIsNamed(t *testing.T) {
	h, _ := auditHarness(t)
	page := h.page(t, "/admin/audit")
	if !strings.Contains(page, msg.T("admin.audit.missing.label")) {
		t.Fatal("the page does not say that a store did not answer")
	}
	name := msg.T("admin.audit.missing.item", "verifier-results", "verifier-inji") + " " + msg.T("admin.audit.reason.code", "unavailable")
	if !strings.Contains(page, name) {
		t.Fatalf("the page does not name the store: want %q", name)
	}
	if !strings.Contains(page, "<td>issued.Revoke") {
		t.Error("the page lost the events of the stores that answered")
	}
}

func TestAuditPageFilters(t *testing.T) {
	h, _ := auditHarness(t)
	cases := map[string]struct {
		query      string
		want, miss []string
	}{
		"source":  {"source=issuer-auth", []string{"<td>auth.Login"}, []string{"<td>issued.Revoke", "<td>admin.Login"}},
		"action":  {"action=auth.Login", []string{"kc|grace"}, []string{"<td>auth.Register"}},
		"actor":   {"actor=kc%7Cada", []string{"<td>issuance.Issue"}, []string{"kc|grace"}},
		"outcome": {"outcome=failure", []string{msg.T("audit.reason.provider")}, []string{"<td>issuance.Issue"}},
		"time":    {"from=2026-03-02&to=2026-03-02", []string{"<td>issued.Revoke"}, []string{"<td>admin.Login"}},
		"admin":   {"source=admin", []string{"<td>admin.Login"}, []string{"<td>issued.Revoke"}},
	}
	for name, c := range cases {
		page := h.page(t, "/admin/audit?"+c.query)
		for _, w := range c.want {
			if !strings.Contains(page, w) {
				t.Errorf("%s: the page misses %q", name, w)
			}
		}
		for _, m := range c.miss {
			if strings.Contains(page, m) {
				t.Errorf("%s: the page shows %q", name, m)
			}
		}
	}
	bad := h.page(t, "/admin/audit?from=yesterday")
	if !strings.Contains(bad, msg.T("admin.audit.date.error")) {
		t.Error("a bad date gives no hint")
	}
}

// TestAuditExportCSV exports the merged events with the filters of the
// page as a CSV file.
func TestAuditExportCSV(t *testing.T) {
	h, _ := auditHarness(t)
	res, err := h.client.Get(h.server.URL + "/admin/audit/export.csv?source=issuer-auth")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/csv") ||
		!strings.Contains(res.Header.Get("Content-Disposition"), "audit") {
		t.Fatalf("status = %d headers = %v", res.StatusCode, res.Header)
	}
	rows, err := csv.NewReader(res.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0][0] != "time" {
		t.Fatalf("rows = %q", rows)
	}
	if rows[1][1] != "issuer-waltid" || rows[1][2] != "issuer-auth" || rows[1][4] != "auth.Login" || rows[1][6] != "success" {
		t.Fatalf("first row = %q", rows[1])
	}
	page := h.page(t, "/admin/audit?source=issuer-auth")
	if !strings.Contains(page, `href="/admin/audit/export.csv?`) {
		t.Error("the page has no export link")
	}
}

func TestAuditExportNeedsASession(t *testing.T) {
	h := newHarness(t, false)
	status, _ := h.get(t, "/admin/audit/export.csv")
	if status != http.StatusSeeOther {
		t.Fatalf("status = %d", status)
	}
}

// TestAuditRetentionPrunesEveryStore sets the retention days in this
// store and in every live peer store, and names the partial outcome.
func TestAuditRetentionPrunesEveryStore(t *testing.T) {
	h, stores := auditHarness(t)
	if !strings.Contains(h.page(t, "/admin/audit"), msg.T("admin.audit.retention.forever")) {
		t.Error("the page does not say that the stores keep every event")
	}
	status, _ := h.post(t, "/admin/audit/retention", url.Values{"days": {"30"}})
	if status != http.StatusSeeOther {
		t.Fatalf("status = %d", status)
	}
	for key, l := range stores {
		days, err := l.Retention(context.Background())
		want := 30
		if key == "verifier-inji/verifier-results" {
			want = 0
		}
		if err != nil || days != want {
			t.Errorf("%s: days = %d, %v", key, days, err)
		}
	}
	page := h.page(t, "/admin/audit?notice=retention-partial")
	if !strings.Contains(page, msg.T("admin.audit.retention.current", "30")) || !strings.Contains(page, msg.T("admin.audit.retention.partial")) {
		t.Error("the page does not show the new retention and the partial outcome")
	}
	for _, days := range []string{"-1", "ten", "4000"} {
		if status, _ := h.post(t, "/admin/audit/retention", url.Values{"days": {days}}); status != http.StatusBadRequest {
			t.Errorf("days %q: status = %d", days, status)
		}
	}
}

func TestAuditRetentionWithoutPeersSaves(t *testing.T) {
	h := newHarness(t, false)
	h.signIn(t)
	res, err := h.client.PostForm(h.server.URL+"/admin/audit/retention", url.Values{"days": {"7"}, oidcflow.CSRFField: {h.csrf}})
	if err != nil {
		t.Fatal(err)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if res.StatusCode != http.StatusSeeOther || !strings.HasSuffix(res.Header.Get("Location"), "notice=retention-saved") {
		t.Fatalf("status = %d location = %q", res.StatusCode, res.Header.Get("Location"))
	}
}

// TestAdminAuditServiceNeedsASuperAdmin serves the store of the admin
// to a super admin session only.
func TestAdminAuditServiceNeedsASuperAdmin(t *testing.T) {
	h := newHarness(t, false)
	client := auditv1connect.NewAuditServiceClient(h.server.Client(), h.server.URL)
	if _, err := client.Query(context.Background(), connect.NewRequest(&auditv1.QueryRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session: %v", err)
	}
	h.signIn(t)
	res, err := client.Query(context.Background(), authed(t, h, &auditv1.QueryRequest{}))
	if err != nil {
		t.Fatalf("super admin: %v", err)
	}
	if len(res.Msg.GetEvents()) == 0 || res.Msg.GetEvents()[0].GetSourceService() != "admin" {
		t.Fatalf("events = %+v", res.Msg.GetEvents())
	}
}
