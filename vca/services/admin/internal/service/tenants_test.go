// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/health"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
)

// fakeAdapter is the tenant service of an adapter whose DPG separates
// tenants.
type fakeAdapter struct {
	backendv1connect.UnimplementedTenantBackendServiceHandler
	mu      sync.Mutex
	tenants map[string]*backendv1.DpgTenant
	n       int
	// createErr, when set, fails every CreateTenant.
	createErr error
	// getErr, when set, fails every GetTenant.
	getErr error
	// creds holds the client credentials per stack tenant id.
	creds map[string][]*backendv1.ClientCredential
	// credErr, when set, fails every credential call.
	credErr error
}

func newFakeAdapter() *fakeAdapter {
	return &fakeAdapter{tenants: map[string]*backendv1.DpgTenant{}, creds: map[string][]*backendv1.ClientCredential{}}
}

func (f *fakeAdapter) CreateTenant(_ context.Context, req *connect.Request[backendv1.CreateTenantRequest]) (*connect.Response[backendv1.CreateTenantResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.n++
	id := fmt.Sprintf("org-%d", f.n)
	t := &backendv1.DpgTenant{Id: id, Name: req.Msg.GetName(), AgentType: req.Msg.GetAgentType(), Dids: []string{"did:key:z6Mk" + id}}
	f.tenants[id] = t
	return connect.NewResponse(&backendv1.CreateTenantResponse{Tenant: t}), nil
}

func (f *fakeAdapter) GetTenant(_ context.Context, req *connect.Request[backendv1.GetTenantRequest]) (*connect.Response[backendv1.GetTenantResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	t, ok := f.tenants[req.Msg.GetId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no tenant"))
	}
	return connect.NewResponse(&backendv1.GetTenantResponse{Tenant: t}), nil
}

func (f *fakeAdapter) DeleteTenant(_ context.Context, req *connect.Request[backendv1.DeleteTenantRequest]) (*connect.Response[backendv1.DeleteTenantResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.tenants[req.Msg.GetId()]; !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no tenant"))
	}
	delete(f.tenants, req.Msg.GetId())
	return connect.NewResponse(&backendv1.DeleteTenantResponse{}), nil
}

func (f *fakeAdapter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tenants)
}

// deployment is a snapshot the test can change: one stack with tenancy
// and one without.
type deployment struct {
	mu   sync.Mutex
	snap topology.Snapshot
}

func (d *deployment) get(context.Context) topology.Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snap
}

// stop marks every pair of a stack absent.
func (d *deployment) stop(dpg configv1.Dpg) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.snap.Peers {
		if d.snap.Peers[i].Peer.Dpg == dpg {
			d.snap.Peers[i].State = topology.Absent
		}
	}
}

// livePair is a live issuer pair whose adapter lists features.
func livePair(dpg configv1.Dpg, url, name string, features ...backendv1.Feature) topology.Status {
	return topology.Status{
		Peer: topology.Peer{
			Pair: topology.PairName(commonv1.Role_ROLE_ISSUER, dpg), Role: commonv1.Role_ROLE_ISSUER, Dpg: dpg,
			Services: map[string]string{topology.AdapterService(dpg): url},
		},
		State:        topology.Live,
		Capabilities: &backendv1.GetCapabilitiesResponse{Features: features, DpgInfo: &backendv1.DpgInfo{DisplayName: name}},
	}
}

// withStacks rebuilds the service of the harness over a deployment with
// a tenancy stack on DPG_CREDEBL, served by the returned fake, and a
// stack without tenancy on DPG_WALTID. The tenancy stack lists the
// extra features too.
func withStacks(t *testing.T, h *harness, extra ...backendv1.Feature) (*fakeAdapter, *deployment) {
	t.Helper()
	fake := newFakeAdapter()
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewTenantBackendServiceHandler(fake))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	dep := &deployment{snap: topology.Snapshot{Peers: []topology.Status{
		livePair(configv1.Dpg_DPG_WALTID, "http://plain.invalid", "Plain stack"),
		livePair(configv1.Dpg_DPG_CREDEBL, srv.URL, "Tenancy stack", append([]backendv1.Feature{backendv1.Feature_FEATURE_MULTI_TENANCY}, extra...)...),
	}}}
	svc, err := service.New(service.Deps{
		Cfg: h.cfg, Records: h.rec, Audit: h.log, Login: h.login, Providers: h.svc.Providers(),
		Vault: onboard.NewVault(""), Fetch: http.DefaultClient, Trust: h.trust,
		Health: health.New(nil, time.Second, nil), Stacks: stacks.New(dep.get, srv.Client()),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return fake, dep
}

func TestCreateTenantBindsToStacks(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h)
	ctx := context.Background()
	res, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{
		DisplayName: "Ministry of Health", Stacks: []configv1.Dpg{configv1.Dpg_DPG_CREDEBL, configv1.Dpg_DPG_CREDEBL},
		AgentType: backendv1.DpgTenant_AGENT_TYPE_DEDICATED,
	}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenant := res.Msg.GetTenant()
	if len(tenant.GetBindings()) != 1 {
		t.Fatalf("bindings = %+v", tenant.GetBindings())
	}
	b := tenant.GetBindings()[0]
	if b.GetStack() != configv1.Dpg_DPG_CREDEBL || b.GetStackName() != "Tenancy stack" || b.GetTenant().GetId() != "org-1" ||
		b.GetTenant().GetName() != "Ministry of Health" || b.GetTenant().GetAgentType() != backendv1.DpgTenant_AGENT_TYPE_DEDICATED ||
		b.GetTenant().GetDids()[0] != "did:key:z6Mkorg-1" || b.GetBoundAt() == nil {
		t.Fatalf("binding = %+v", b)
	}
	if fake.count() != 1 {
		t.Fatalf("the stack holds %d tenants, want 1", fake.count())
	}
	// The binding survives in the record and in the list.
	list, err := h.svc.ListTenants(ctx, request(h, &adminv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tn := range list.Msg.GetTenants() {
		if tn.GetId() == tenant.GetId() {
			found = len(tn.GetBindings()) == 1 && tn.GetBindings()[0].GetTenant().GetId() == "org-1"
		}
	}
	if !found {
		t.Error("the list lost the binding")
	}
	if recs := auditActions(t, h, "admin.CreateTenant"); len(recs) != 1 || recs[0].Target != tenant.GetId() || !recs[0].OK {
		t.Errorf("audit = %+v", recs)
	}
}

func TestCreateTenantRefusesAStackWithoutTenancy(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h)
	ctx := context.Background()
	before, err := h.rec.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, dpg := range []configv1.Dpg{configv1.Dpg_DPG_WALTID, configv1.Dpg_DPG_INJI} {
		_, cerr := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{
			DisplayName: "Ministry", Stacks: []configv1.Dpg{configv1.Dpg_DPG_CREDEBL, dpg},
		}))
		if connect.CodeOf(cerr) != connect.CodeFailedPrecondition {
			t.Errorf("%v: code = %v, %v", dpg, connect.CodeOf(cerr), cerr)
		}
	}
	after, err := h.rec.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || fake.count() != 0 {
		t.Fatalf("a refused create left %d tenants and %d stack tenants", len(after)-len(before), fake.count())
	}
	if recs := auditActions(t, h, "admin.CreateTenant"); len(recs) != 2 || recs[0].OK || recs[1].OK {
		t.Errorf("audit = %+v", recs)
	}
}

func TestCreateTenantRollsBackWhenAStackFails(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h)
	fake.createErr = connect.NewError(connect.CodeUnavailable, errors.New("the platform is down"))
	ctx := context.Background()
	_, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{
		DisplayName: "Ministry", Stacks: []configv1.Dpg{configv1.Dpg_DPG_CREDEBL},
	}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("code = %v, %v", connect.CodeOf(err), err)
	}
	all, err := h.rec.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("the failed create left a tenant: %+v", all)
	}
}

func TestBindAndUnbindTenant(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h)
	ctx := context.Background()
	bound, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{
		Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, AgentType: backendv1.DpgTenant_AGENT_TYPE_SHARED,
	}))
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	if got := bound.Msg.GetTenant().GetBindings(); len(got) != 1 || got[0].GetTenant().GetName() != "Admin tenant" {
		t.Fatalf("bindings = %+v", got)
	}
	if _, cerr := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); connect.CodeOf(cerr) != connect.CodeAlreadyExists {
		t.Errorf("a second bind gave %v", cerr)
	}
	if _, cerr := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_WALTID})); connect.CodeOf(cerr) != connect.CodeFailedPrecondition {
		t.Errorf("a bind on a stack without tenancy gave %v", cerr)
	}
	if _, cerr := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: "missing", Stack: configv1.Dpg_DPG_CREDEBL})); connect.CodeOf(cerr) != connect.CodeNotFound {
		t.Errorf("a bind of an unknown tenant gave %v", cerr)
	}
	if fake.count() != 1 {
		t.Fatalf("the stack holds %d tenants, want 1", fake.count())
	}
	unbound, err := h.svc.UnbindTenant(ctx, request(h, &adminv1.UnbindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL}))
	if err != nil || len(unbound.Msg.GetTenant().GetBindings()) != 0 {
		t.Fatalf("UnbindTenant = %+v, %v", unbound, err)
	}
	if fake.count() != 0 {
		t.Fatal("the stack kept its tenant")
	}
	if _, err := h.svc.UnbindTenant(ctx, request(h, &adminv1.UnbindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a second unbind gave %v", err)
	}
	recs := auditActions(t, h, "admin.BindTenant")
	ok := 0
	for _, r := range recs {
		if r.OK {
			ok++
			if r.Target != h.tenantID {
				t.Errorf("the bind record names %q", r.Target)
			}
		}
	}
	if len(recs) != 4 || ok != 1 {
		t.Errorf("bind audit = %+v", recs)
	}
	if recs := auditActions(t, h, "admin.UnbindTenant"); len(recs) != 2 {
		t.Errorf("unbind audit = %+v", recs)
	}
}

func TestUnbindToleratesAStackTenantThatIsGone(t *testing.T) {
	h := newHarness(t)
	fake, dep := withStacks(t, h)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.tenants = map[string]*backendv1.DpgTenant{}
	fake.mu.Unlock()
	if _, err := h.svc.UnbindTenant(ctx, request(h, &adminv1.UnbindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatalf("UnbindTenant: %v", err)
	}
	// A stack that does not run cannot delete its tenant, so the unbind
	// waits for it.
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	dep.stop(configv1.Dpg_DPG_CREDEBL)
	if _, err := h.svc.UnbindTenant(ctx, request(h, &adminv1.UnbindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("an unbind on a stopped stack gave %v", err)
	}
}

func TestGetTenantReadsTheStackTenant(t *testing.T) {
	h := newHarness(t)
	fake, dep := withStacks(t, h)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	// The stack tenant gained a DID after the binding.
	fake.mu.Lock()
	fake.tenants["org-1"].Dids = append(fake.tenants["org-1"].Dids, "did:web:health.example")
	fake.mu.Unlock()
	got, err := h.svc.GetTenant(ctx, request(h, &adminv1.GetTenantRequest{Id: h.tenantID}))
	if err != nil {
		t.Fatal(err)
	}
	b := got.Msg.GetTenant().GetBindings()[0]
	if len(b.GetTenant().GetDids()) != 2 || b.GetError() != "" {
		t.Fatalf("binding = %+v", b)
	}
	fake.getErr = connect.NewError(connect.CodeUnavailable, errors.New("the platform is down"))
	got, err = h.svc.GetTenant(ctx, request(h, &adminv1.GetTenantRequest{Id: h.tenantID}))
	if err != nil {
		t.Fatal(err)
	}
	if b := got.Msg.GetTenant().GetBindings()[0]; b.GetError() == "" || b.GetTenant().GetId() != "org-1" {
		t.Fatalf("a failed read gave %+v", b)
	}
	dep.stop(configv1.Dpg_DPG_CREDEBL)
	got, err = h.svc.GetTenant(ctx, request(h, &adminv1.GetTenantRequest{Id: h.tenantID}))
	if err != nil {
		t.Fatal(err)
	}
	if b := got.Msg.GetTenant().GetBindings()[0]; b.GetError() == "" {
		t.Fatalf("a stopped stack gave %+v", b)
	}
}

func TestDeleteTenantDeletesTheStackTenants(t *testing.T) {
	h := newHarness(t)
	fake, dep := withStacks(t, h)
	ctx := context.Background()
	res, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{
		DisplayName: "Ministry", Stacks: []configv1.Dpg{configv1.Dpg_DPG_CREDEBL},
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := res.Msg.GetTenant().GetId()
	if _, cerr := h.svc.DeleteTenant(ctx, request(h, &adminv1.DeleteTenantRequest{Id: id})); cerr != nil {
		t.Fatalf("DeleteTenant: %v", cerr)
	}
	if fake.count() != 0 {
		t.Fatal("the stack kept its tenant")
	}
	// A stopped stack keeps the tenant: the admin starts the stack first.
	res, err = h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{
		DisplayName: "Ministry", Stacks: []configv1.Dpg{configv1.Dpg_DPG_CREDEBL},
	}))
	if err != nil {
		t.Fatal(err)
	}
	dep.stop(configv1.Dpg_DPG_CREDEBL)
	if _, err := h.svc.DeleteTenant(ctx, request(h, &adminv1.DeleteTenantRequest{Id: res.Msg.GetTenant().GetId()})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a delete with a stopped stack gave %v", err)
	}
	if _, err := h.rec.GetTenant(ctx, res.Msg.GetTenant().GetId()); err != nil {
		t.Fatalf("the refused delete removed the tenant: %v", err)
	}
}

func TestTenantRPCsWithoutStacksRefuseABinding(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{
		DisplayName: "Ministry", Stacks: []configv1.Dpg{configv1.Dpg_DPG_CREDEBL},
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("CreateTenant = %v", err)
	}
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("BindTenant = %v", err)
	}
	for _, call := range []func() error{
		func() error {
			_, err := h.svc.BindTenant(ctx, connect.NewRequest(&adminv1.BindTenantRequest{}))
			return err
		},
		func() error {
			_, err := h.svc.UnbindTenant(ctx, connect.NewRequest(&adminv1.UnbindTenantRequest{}))
			return err
		},
	} {
		if connect.CodeOf(call()) != connect.CodeUnauthenticated {
			t.Error("an anonymous caller passed")
		}
	}
}
