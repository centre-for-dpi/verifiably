// SPDX-License-Identifier: Apache-2.0

package portal_test

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
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
)

// fakeStack is the adapter of a stack: its capability answer and its
// tenant service.
type fakeStack struct {
	backendv1connect.UnimplementedCapabilityServiceHandler
	backendv1connect.UnimplementedTenantBackendServiceHandler
	name     string
	version  string
	features []backendv1.Feature
	mu       sync.Mutex
	tenants  map[string]*backendv1.DpgTenant
	n        int
	// mint, when set, makes the id and the DIDs of a new tenant.
	mint func(n int) (string, []string)
	// creds holds the client credentials per stack tenant id.
	creds map[string][]*backendv1.ClientCredential
}

func newFakeStack(name string, features ...backendv1.Feature) *fakeStack {
	return &fakeStack{
		name: name, features: features,
		tenants: map[string]*backendv1.DpgTenant{}, creds: map[string][]*backendv1.ClientCredential{},
	}
}

func (f *fakeStack) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		Features: f.features, DpgInfo: &backendv1.DpgInfo{DisplayName: f.name, Version: f.version},
	}), nil
}

func (f *fakeStack) CreateTenant(_ context.Context, req *connect.Request[backendv1.CreateTenantRequest]) (*connect.Response[backendv1.CreateTenantResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id, dids := fmt.Sprintf("org-%d", f.n), []string{fmt.Sprintf("did:key:z6Mkorg-%d", f.n)}
	if f.mint != nil {
		id, dids = f.mint(f.n)
	}
	t := &backendv1.DpgTenant{Id: id, Name: req.Msg.GetName(), AgentType: req.Msg.GetAgentType(), Dids: dids}
	f.tenants[id] = t
	return connect.NewResponse(&backendv1.CreateTenantResponse{Tenant: t}), nil
}

func (f *fakeStack) GetTenant(_ context.Context, req *connect.Request[backendv1.GetTenantRequest]) (*connect.Response[backendv1.GetTenantResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tenants[req.Msg.GetId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no tenant"))
	}
	return connect.NewResponse(&backendv1.GetTenantResponse{Tenant: t}), nil
}

func (f *fakeStack) DeleteTenant(_ context.Context, req *connect.Request[backendv1.DeleteTenantRequest]) (*connect.Response[backendv1.DeleteTenantResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tenants, req.Msg.GetId())
	return connect.NewResponse(&backendv1.DeleteTenantResponse{}), nil
}

func (f *fakeStack) ListClientCredentials(_ context.Context, req *connect.Request[backendv1.ListClientCredentialsRequest]) (*connect.Response[backendv1.ListClientCredentialsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return connect.NewResponse(&backendv1.ListClientCredentialsResponse{Credentials: f.creds[req.Msg.GetTenantId()]}), nil
}

func (f *fakeStack) CreateClientCredential(_ context.Context, req *connect.Request[backendv1.CreateClientCredentialRequest]) (*connect.Response[backendv1.CreateClientCredentialResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	c := &backendv1.ClientCredential{
		Id: fmt.Sprintf("cred-%d", f.n), ClientId: fmt.Sprintf("client-%d", f.n), Name: req.Msg.GetName(),
		CreatedAt: timestamppb.New(time.Date(2026, 9, 24, 9, 30, 0, 0, time.UTC)),
	}
	f.creds[req.Msg.GetTenantId()] = append(f.creds[req.Msg.GetTenantId()], c)
	return connect.NewResponse(&backendv1.CreateClientCredentialResponse{Credential: c, ClientSecret: fmt.Sprintf("stack-secret-%d", f.n)}), nil
}

func (f *fakeStack) DeleteClientCredential(_ context.Context, req *connect.Request[backendv1.DeleteClientCredentialRequest]) (*connect.Response[backendv1.DeleteClientCredentialResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.creds[req.Msg.GetTenantId()]
	for i, c := range list {
		if c.GetId() == req.Msg.GetId() {
			f.creds[req.Msg.GetTenantId()] = append(list[:i], list[i+1:]...)
		}
	}
	return connect.NewResponse(&backendv1.DeleteClientCredentialResponse{}), nil
}

func (f *fakeStack) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tenants)
}

// serve starts the adapter of the stack.
func (f *fakeStack) serve(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(f))
	mux.Handle(backendv1connect.NewTenantBackendServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// stackPeers is a deployment of this admin pair and one live issuer pair
// per stack: the tenancy stack on DPG_CREDEBL and the plain stack on
// DPG_WALTID. A nil stack leaves its pair out.
func stackPeers(tenancy, plain *fakeStack) func(*testing.T, *harness) func(*config.Config, *app.Deps) {
	return func(t *testing.T, h *harness) func(*config.Config, *app.Deps) {
		t.Helper()
		ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mustWrite(t, w, []byte("ready"))
		}))
		t.Cleanup(ready.Close)
		peers := []topology.Peer{
			{Pair: "admin-waltid", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: h.server.URL,
				Services: map[string]string{"admin": ready.URL}},
		}
		add := func(f *fakeStack, dpg configv1.Dpg) {
			if f == nil {
				return
			}
			peers = append(peers, topology.Peer{
				Pair: topology.PairName(commonv1.Role_ROLE_ISSUER, dpg), Role: commonv1.Role_ROLE_ISSUER, Dpg: dpg,
				PublicURL: "https://" + topology.PairName(commonv1.Role_ROLE_ISSUER, dpg) + ".example",
				Services:  map[string]string{"schema-registry": ready.URL, topology.AdapterService(dpg): f.serve(t)},
			})
		}
		add(plain, configv1.Dpg_DPG_WALTID)
		add(tenancy, configv1.Dpg_DPG_CREDEBL)
		return func(cfg *config.Config, deps *app.Deps) {
			cfg.Peers = peers
			deps.Prober = &topology.Prober{Peers: peers, Lookup: func(context.Context, string) ([]string, error) {
				return []string{"127.0.0.1"}, nil
			}}
		}
	}
}
