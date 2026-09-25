// SPDX-License-Identifier: Apache-2.0

package stacks_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
)

// live is one live pair of a stack whose adapter answered.
func live(pair string, role commonv1.Role, dpg configv1.Dpg, adapter, name string, features ...backendv1.Feature) topology.Status {
	svc := topology.AdapterService(dpg)
	return topology.Status{
		Peer:  topology.Peer{Pair: pair, Role: role, Dpg: dpg, Services: map[string]string{svc: adapter}},
		State: topology.Live,
		Capabilities: &backendv1.GetCapabilitiesResponse{
			Features: features, DpgInfo: &backendv1.DpgInfo{DisplayName: name},
		},
	}
}

func snapshot() topology.Snapshot {
	return topology.Snapshot{Peers: []topology.Status{
		// The admin pair runs no adapter.
		{Peer: topology.Peer{Pair: "admin-waltid", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}, State: topology.Live},
		live("issuer-waltid", commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID, "http://waltid", "Plain stack"),
		live("issuer-credebl", commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_CREDEBL, "http://credebl", "Tenancy stack",
			backendv1.Feature_FEATURE_MULTI_TENANCY, backendv1.Feature_FEATURE_WEBHOOKS),
		// A second pair of the same stack adds nothing.
		live("verifier-credebl", commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_CREDEBL, "http://credebl-2", "Tenancy stack",
			backendv1.Feature_FEATURE_MULTI_TENANCY),
		// A starting pair is not a stack yet.
		{Peer: topology.Peer{Pair: "issuer-inji", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI,
			Services: map[string]string{"dpg-adapter-inji": "http://inji"}}, State: topology.Starting},
	}}
}

func TestListGivesOneStackPerLiveAdapter(t *testing.T) {
	got := stacks.List(snapshot())
	if len(got) != 2 {
		t.Fatalf("got %d stacks, want 2: %+v", len(got), got)
	}
	if got[0].Dpg != configv1.Dpg_DPG_WALTID || got[0].Name != "Plain stack" || got[0].Adapter != "http://waltid" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Dpg != configv1.Dpg_DPG_CREDEBL || got[1].Adapter != "http://credebl" {
		t.Errorf("second = %+v", got[1])
	}
	if got[0].Has(backendv1.Feature_FEATURE_MULTI_TENANCY) || !got[1].Has(backendv1.Feature_FEATURE_MULTI_TENANCY) {
		t.Error("Has reads the wrong answer")
	}
}

func TestWithKeepsTheStacksThatListAFeature(t *testing.T) {
	got := stacks.With(snapshot(), backendv1.Feature_FEATURE_MULTI_TENANCY)
	if len(got) != 1 || got[0].Name != "Tenancy stack" {
		t.Fatalf("got %+v", got)
	}
	if got := stacks.With(snapshot(), backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestNameFallsBackToTheShortName(t *testing.T) {
	snap := snapshot()
	if got := stacks.Name(snap, configv1.Dpg_DPG_CREDEBL); got != "Tenancy stack" {
		t.Errorf("got %q", got)
	}
	if got := stacks.Name(snap, configv1.Dpg_DPG_INJI); got != "inji" {
		t.Errorf("got %q", got)
	}
	unnamed := topology.Snapshot{Peers: []topology.Status{
		live("issuer-waltid", commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID, "http://waltid", ""),
	}}
	if got := stacks.List(unnamed)[0].Name; got != "waltid" {
		t.Errorf("got %q", got)
	}
}

// tenants is a fake tenant service of an adapter.
type tenants struct {
	backendv1connect.UnimplementedTenantBackendServiceHandler
}

func (tenants) ListTenants(context.Context, *connect.Request[backendv1.ListTenantsRequest]) (*connect.Response[backendv1.ListTenantsResponse], error) {
	return connect.NewResponse(&backendv1.ListTenantsResponse{Tenants: []*backendv1.DpgTenant{{Id: "org-1"}}}), nil
}

func TestDirectoryFindsAStackAndCallsItsAdapter(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewTenantBackendServiceHandler(tenants{}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	snap := topology.Snapshot{Peers: []topology.Status{
		live("issuer-credebl", commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_CREDEBL, srv.URL, "Tenancy stack", backendv1.Feature_FEATURE_MULTI_TENANCY),
		live("issuer-waltid", commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID, "http://waltid", "Plain stack"),
	}}
	d := stacks.New(func(context.Context) topology.Snapshot { return snap }, srv.Client())
	ctx := context.Background()
	if got := d.List(ctx); len(got) != 2 {
		t.Fatalf("List = %+v", got)
	}
	st, err := d.Find(ctx, configv1.Dpg_DPG_CREDEBL, backendv1.Feature_FEATURE_MULTI_TENANCY)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	res, err := d.Tenants(st).ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
	if err != nil || res.Msg.GetTenants()[0].GetId() != "org-1" {
		t.Fatalf("ListTenants = %v, %v", res, err)
	}
	if _, err := d.Find(ctx, configv1.Dpg_DPG_WALTID, backendv1.Feature_FEATURE_MULTI_TENANCY); !errors.Is(err, stacks.ErrNotOffered) {
		t.Errorf("a stack without the feature gave %v", err)
	}
	if _, err := d.Find(ctx, configv1.Dpg_DPG_INJI, backendv1.Feature_FEATURE_MULTI_TENANCY); !errors.Is(err, stacks.ErrNotOffered) {
		t.Errorf("a stack that does not run gave %v", err)
	}
}

func TestANilDirectoryOffersNothing(t *testing.T) {
	var d *stacks.Directory
	ctx := context.Background()
	if got := d.List(ctx); got != nil {
		t.Errorf("List = %+v", got)
	}
	if _, err := d.Find(ctx, configv1.Dpg_DPG_CREDEBL, backendv1.Feature_FEATURE_MULTI_TENANCY); !errors.Is(err, stacks.ErrNotOffered) {
		t.Errorf("Find = %v", err)
	}
	if got := stacks.New(nil, nil).List(ctx); got != nil {
		t.Errorf("a directory without a snapshot lists %+v", got)
	}
}
