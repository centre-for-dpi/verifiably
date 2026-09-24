// SPDX-License-Identifier: Apache-2.0

package fanout_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/fanout"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

const token = "admin-session-token"

// authService is one fake auth service: the provider RPCs over a
// registry that accepts the admin session token.
type authService struct {
	registry *oidcflow.Registry
	server   *httptest.Server
	calls    int
}

func newAuthService(t *testing.T, role string, down bool) *authService {
	t.Helper()
	registry, err := oidcflow.NewRegistry(oidcflow.NewMemoryPersister(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &authService{registry: registry}
	mux := http.NewServeMux()
	path, handler := oidcflow.NewAdminHandler(oidcflow.AdminProviders{
		Registry: registry, Authorize: oidcflow.BearerAuthorizer(token), Roles: []string{role},
	})
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.calls++
		if down {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	a.server = httptest.NewServer(mux)
	t.Cleanup(a.server.Close)
	return a
}

// deployment is a snapshot with one fake auth service per live pair.
type deployment struct {
	snap topology.Snapshot
	auth map[string]*authService
}

func newDeployment(t *testing.T, states map[string]topology.State, down map[string]bool) *deployment {
	t.Helper()
	d := &deployment{auth: map[string]*authService{}}
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER, commonv1.Role_ROLE_ADMIN} {
		for _, dpg := range []configv1.Dpg{configv1.Dpg_DPG_WALTID, configv1.Dpg_DPG_INJI, configv1.Dpg_DPG_CREDEBL} {
			pair := topology.PairName(role, dpg)
			peer := topology.Peer{Pair: pair, Role: role, Dpg: dpg, PublicURL: "https://" + pair + ".example", Services: map[string]string{}}
			state, ok := states[pair]
			if !ok {
				state = topology.Live
			}
			if name := topology.AuthService(role); name != "" && state != topology.Absent {
				svc := newAuthService(t, strings.TrimPrefix(strings.ToLower(role.String()), "role_"), down[pair])
				d.auth[pair] = svc
				peer.Services[name] = svc.server.URL
			}
			d.snap.Peers = append(d.snap.Peers, topology.Status{Peer: peer, State: state})
		}
	}
	return d
}

func (d *deployment) fanout(t *testing.T) *fanout.FanOut {
	t.Helper()
	f, err := fanout.New(fanout.Options{Snapshot: func(context.Context) topology.Snapshot { return d.snap }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func provider() oidcflow.Provider {
	return oidcflow.Provider{
		ID: "national", DisplayName: "National IdP", DiscoveryURL: "https://idp.example/realms/x/.well-known/openid-configuration",
		ClientID: "vca", Enabled: true, Roles: []string{"issuer", "holder"},
		Profile: oidcflow.Profile{Kind: oidcflow.KindKeycloak, Stacks: []string{"waltid"}},
	}
}

// pairs lists the pair names of a report in order.
func pairs(results []fanout.Result) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.Target.Pair)
	}
	return out
}

func TestFanOutTargetsRolesAndStacks(t *testing.T) {
	d := newDeployment(t, nil, nil)
	report := d.fanout(t).Push(context.Background(), token, provider())
	if got := pairs(report.Results); strings.Join(got, ",") != "issuer-waltid,holder-waltid" {
		t.Fatalf("targets %v", got)
	}
	if !report.OK() || len(report.Failed()) != 0 {
		t.Fatalf("report %s", report)
	}
	for _, pair := range []string{"issuer-waltid", "holder-waltid"} {
		list := d.auth[pair].registry.List()
		if len(list) != 1 || list[0].ClientID != "vca" {
			t.Fatalf("%s holds %+v", pair, list)
		}
	}
	for _, pair := range []string{"issuer-inji", "verifier-waltid", "holder-credebl"} {
		if d.auth[pair].calls != 0 {
			t.Fatalf("%s was called", pair)
		}
	}
	// Every result names the id the auth service gave the record.
	for _, r := range report.Results {
		if r.ProviderID == "" || !r.Created {
			t.Fatalf("result %+v", r)
		}
	}
	// No stack means every stack; the admin role has no auth service.
	p := provider()
	p.Stacks = nil
	p.Roles = []string{"verifier", "admin"}
	report = d.fanout(t).Push(context.Background(), token, p)
	if got := pairs(report.Results); strings.Join(got, ",") != "verifier-waltid,verifier-inji,verifier-credebl" {
		t.Fatalf("targets %v", got)
	}
	// No role means no target.
	p.Roles = nil
	if report = d.fanout(t).Push(context.Background(), token, p); len(report.Results) != 0 || !report.OK() {
		t.Fatalf("no roles: %s", report)
	}
}

func TestFanOutReportsPartialFailure(t *testing.T) {
	d := newDeployment(t, nil, map[string]bool{"holder-waltid": true})
	report := d.fanout(t).Push(context.Background(), token, provider())
	if report.OK() {
		t.Fatal("a failed target reports ok")
	}
	failed := report.Failed()
	if len(failed) != 1 || failed[0].Target.Pair != "holder-waltid" || failed[0].Err == nil {
		t.Fatalf("failed %+v", failed)
	}
	if len(d.auth["issuer-waltid"].registry.List()) != 1 {
		t.Fatal("the live target did not get the provider")
	}
	text := report.String()
	if !strings.Contains(text, "holder-waltid") || !strings.Contains(text, "1 of 2") {
		t.Fatalf("report text %q", text)
	}
	// A wrong token fails at every target, and the error names the code.
	report = d.fanout(t).Push(context.Background(), "wrong", provider())
	if len(report.Failed()) != 2 || connect.CodeOf(report.Failed()[0].Err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong token: %s", report)
	}
	// No token is reported without a call.
	report = d.fanout(t).Push(context.Background(), "", provider())
	if len(report.Failed()) != 2 || !errors.Is(report.Failed()[0].Err, fanout.ErrNoToken) {
		t.Fatalf("no token: %s", report)
	}
}

func TestFanOutSkipsAbsentPairs(t *testing.T) {
	d := newDeployment(t, map[string]topology.State{"holder-waltid": topology.Absent, "issuer-inji": topology.Starting}, nil)
	p := provider()
	p.Stacks = []string{"waltid", "inji"}
	report := d.fanout(t).Push(context.Background(), token, p)
	if got := pairs(report.Results); strings.Join(got, ",") != "issuer-waltid,holder-inji" {
		t.Fatalf("targets %v", got)
	}
	if d.auth["issuer-inji"].calls != 0 {
		t.Fatal("a starting pair was called")
	}
	// A live pair without an auth URL cannot be a target.
	d.snap.Peers[0].Peer.Services = map[string]string{}
	if got := pairs(d.fanout(t).Push(context.Background(), token, p).Results); strings.Join(got, ",") != "holder-inji" {
		t.Fatalf("targets without auth %v", got)
	}
}

func TestFanOutIsIdempotent(t *testing.T) {
	d := newDeployment(t, nil, nil)
	f := d.fanout(t)
	first := f.Push(context.Background(), token, provider())
	p := provider()
	p.DisplayName = "National IdP, renamed"
	second := f.Push(context.Background(), token, p)
	if !first.OK() || !second.OK() {
		t.Fatalf("reports %s %s", first, second)
	}
	for i, r := range second.Results {
		if r.Created || r.ProviderID != first.Results[i].ProviderID {
			t.Fatalf("second push %+v, first %+v", r, first.Results[i])
		}
	}
	for _, pair := range []string{"issuer-waltid", "holder-waltid"} {
		list := d.auth[pair].registry.List()
		if len(list) != 1 || list[0].DisplayName != "National IdP, renamed" {
			t.Fatalf("%s holds %+v", pair, list)
		}
	}
}

func TestNewNeedsASnapshot(t *testing.T) {
	if _, err := fanout.New(fanout.Options{}); err == nil {
		t.Fatal("a fan out without a snapshot built")
	}
}
