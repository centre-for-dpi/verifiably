// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/fanout"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/health"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The service must satisfy the generated handler interface.
var _ adminv1connect.AdminServiceHandler = (*service.Service)(nil)

// fakeTrust is a trust registry client in process.
type fakeTrust struct {
	trustv1connect.TrustServiceClient
	entries    map[string]*trustv1.TrustEntry
	registries []*trustv1.Registry
	err        error
	// actors holds the actor header of each change, in call order.
	actors []string
}

func newFakeTrust() *fakeTrust {
	return &fakeTrust{entries: map[string]*trustv1.TrustEntry{}}
}

func key(id *trustv1.TrustEntry_Identifier) string {
	if id.GetDid() != "" {
		return id.GetDid()
	}
	return id.GetX509Subject()
}

func (f *fakeTrust) UpsertEntry(_ context.Context, req *connect.Request[trustv1.UpsertEntryRequest]) (*connect.Response[trustv1.UpsertEntryResponse], error) {
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	if f.err != nil {
		return nil, f.err
	}
	entry := req.Msg.GetEntry()
	f.entries[key(entry.GetIdentifier())] = entry
	return connect.NewResponse(&trustv1.UpsertEntryResponse{Entry: entry}), nil
}

func (f *fakeTrust) GetEntry(_ context.Context, req *connect.Request[trustv1.GetEntryRequest]) (*connect.Response[trustv1.GetEntryResponse], error) {
	entry, ok := f.entries[key(req.Msg.GetIdentifier())]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no entry"))
	}
	return connect.NewResponse(&trustv1.GetEntryResponse{Entry: entry}), nil
}

func (f *fakeTrust) ListEntries(_ context.Context, req *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	res := &trustv1.ListEntriesResponse{Page: &commonv1.PageResult{}}
	for _, e := range f.entries {
		if st := req.Msg.GetStatus(); st != trustv1.Status_STATUS_UNSPECIFIED && e.GetStatus() != st {
			continue
		}
		res.Entries = append(res.Entries, e)
	}
	res.Page.TotalSize = int64(len(res.Entries))
	return connect.NewResponse(res), nil
}

func (f *fakeTrust) DeleteEntry(_ context.Context, req *connect.Request[trustv1.DeleteEntryRequest]) (*connect.Response[trustv1.DeleteEntryResponse], error) {
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	delete(f.entries, key(req.Msg.GetIdentifier()))
	return connect.NewResponse(&trustv1.DeleteEntryResponse{}), nil
}

func (f *fakeTrust) AddRegistry(_ context.Context, req *connect.Request[trustv1.AddRegistryRequest]) (*connect.Response[trustv1.AddRegistryResponse], error) {
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	if f.err != nil {
		return nil, f.err
	}
	r := req.Msg.GetRegistry()
	r.Id = "reg-1"
	f.registries = append(f.registries, r)
	return connect.NewResponse(&trustv1.AddRegistryResponse{Registry: r}), nil
}

func (f *fakeTrust) ListRegistries(context.Context, *connect.Request[trustv1.ListRegistriesRequest]) (*connect.Response[trustv1.ListRegistriesResponse], error) {
	return connect.NewResponse(&trustv1.ListRegistriesResponse{Registries: f.registries, JwksUrl: "https://trust.example/.well-known/jwks.json"}), nil
}

func (f *fakeTrust) RemoveRegistry(_ context.Context, req *connect.Request[trustv1.RemoveRegistryRequest]) (*connect.Response[trustv1.RemoveRegistryResponse], error) {
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	for i, r := range f.registries {
		if r.GetId() == req.Msg.GetId() {
			f.registries = append(f.registries[:i], f.registries[i+1:]...)
			return connect.NewResponse(&trustv1.RemoveRegistryResponse{}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no registry"))
}

func (f *fakeTrust) SyncRegistry(_ context.Context, req *connect.Request[trustv1.SyncRegistryRequest]) (*connect.Response[trustv1.SyncRegistryResponse], error) {
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	for _, r := range f.registries {
		if r.GetId() == req.Msg.GetId() {
			return connect.NewResponse(&trustv1.SyncRegistryResponse{Registry: r}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no registry"))
}

// harness holds the service and the values a test needs.
type harness struct {
	svc      *service.Service
	rec      *records.Store
	log      *auditlog.Log
	trust    *fakeTrust
	idp      *oidctest.Provider
	login    *login.Service
	admin    string
	tenantID string
	idpSrv   *httptest.Server
	health   *httptest.Server
	cfg      config.Config
}

// newHarness wires the service over memory stores and a fake provider.
func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.idp = oidctest.New()
	t.Cleanup(h.idp.Close)
	h.idpSrv = registrationIDP(t, h.idp)
	h.health = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(health.VersionHeader, "1.0.0")
		mustWrite(t, w, []byte("ready"))
	}))
	t.Cleanup(h.health.Close)
	kv := store.Memory()
	rec, err := records.New(kv, nil)
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	log, err := auditlog.New(kv, nil)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	registry, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, serr := registry.Put(oidcflow.Provider{
		ID: "idp", DisplayName: "Test IdP", DiscoveryURL: h.idp.DiscoveryURL(),
		ClientID: h.idp.ClientID, Enabled: true,
	}); serr != nil {
		t.Fatalf("Put: %v", serr)
	}
	signKey, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h.cfg = config.Config{
		PublicURL: "https://admin.example", RedirectURI: "https://admin.example/auth/callback",
		CookieName: "vca_admin_session", SessionTTL: 15 * time.Minute, Timeout: 5 * time.Second,
		Services: []string{"trust-registry=" + h.health.URL},
	}
	signer, err := oidcflow.NewSigner(signKey, h.cfg.PublicURL, login.Audience, h.cfg.SessionTTL, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	csrf, err := oidcflow.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	cache := oidcflow.NewCache(nil, 0)
	lg, err := login.New(login.Deps{
		Cfg: h.cfg, Flow: &oidcflow.Flow{Cache: cache}, Cache: cache, Providers: registry,
		Signer: signer, CSRF: csrf, Records: rec, Audit: log,
	})
	if err != nil {
		t.Fatalf("login.New: %v", err)
	}
	h.trust = newFakeTrust()
	svc, err := service.New(service.Deps{
		Cfg: h.cfg, Records: rec, Audit: log, Login: lg, Providers: registry,
		Vault: onboard.NewVault(""), Fetch: http.DefaultClient, Trust: h.trust,
		Health: health.New(nil, time.Second, nil),
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	h.svc, h.rec, h.log, h.login = svc, rec, log, lg
	ctx := context.Background()
	tenant, err := rec.CreateTenant(ctx, "Admin tenant")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	h.tenantID = tenant.ID
	_, secret, err := rec.CreateKey(ctx, records.KeySpec{
		DisplayName: "test", TenantID: tenant.ID, Roles: []string{login.RoleAdmin},
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	h.admin = secret
	return h
}

// registrationIDP serves a metadata document with a registration
// endpoint (RFC 7591) beside the fake provider.
func registrationIDP(t *testing.T, idp *oidctest.Provider) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 idp.Issuer(),
			"authorization_endpoint": idp.Issuer() + "/authorize",
			"token_endpoint":         idp.Issuer() + "/token",
			"jwks_uri":               idp.Issuer() + "/jwks",
			"registration_endpoint":  srv.URL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]string{"client_id": "registered", "client_secret": "kept"})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if cerr := json.NewEncoder(w).Encode(v); cerr != nil {
		panic(cerr)
	}
}

// call adds the admin credential to a request.
func (h *harness) call(msg any) http.Header {
	_ = msg
	return http.Header{"Authorization": {"Bearer " + h.admin}}
}

// request builds a Connect request with the admin credential.
func request[T any](h *harness, msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+h.admin)
	return req
}

func TestNewChecksTheDependencies(t *testing.T) {
	if _, err := service.New(service.Deps{}); err == nil {
		t.Fatal("New accepted empty dependencies")
	}
}

func TestEveryRPCNeedsASuperAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.CreateTenant(ctx, connect.NewRequest(&adminv1.CreateTenantRequest{DisplayName: "x"})); err == nil {
		t.Error("CreateTenant accepted an anonymous caller")
	}
	if _, err := h.svc.ListTenants(ctx, connect.NewRequest(&adminv1.ListTenantsRequest{})); err == nil {
		t.Error("ListTenants accepted an anonymous caller")
	}
	if _, err := h.svc.GetServiceHealth(ctx, connect.NewRequest(&adminv1.GetServiceHealthRequest{})); err == nil {
		t.Error("GetServiceHealth accepted an anonymous caller")
	}
	if _, err := h.svc.QueryAuditLog(ctx, connect.NewRequest(&adminv1.QueryAuditLogRequest{})); err == nil {
		t.Error("QueryAuditLog accepted an anonymous caller")
	}
	if _, err := h.svc.UpsertTrustEntry(ctx, connect.NewRequest(&adminv1.UpsertTrustEntryRequest{})); err == nil {
		t.Error("UpsertTrustEntry accepted an anonymous caller")
	}
	if _, err := h.svc.ApproveTrustEntry(ctx, connect.NewRequest(&adminv1.ApproveTrustEntryRequest{})); err == nil {
		t.Error("ApproveTrustEntry accepted an anonymous caller")
	}
	if _, err := h.svc.RejectTrustEntry(ctx, connect.NewRequest(&adminv1.RejectTrustEntryRequest{})); err == nil {
		t.Error("RejectTrustEntry accepted an anonymous caller")
	}
	if _, err := h.svc.ListAuthProviders(ctx, connect.NewRequest(&adminv1.ListAuthProvidersRequest{})); err == nil {
		t.Error("ListAuthProviders accepted an anonymous caller")
	}
}

func TestTenantRPCsAndTheAuditTrail(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{DisplayName: "Ministry"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	id := created.Msg.GetTenant().GetId()
	if id == "" || created.Msg.GetTenant().GetState() != adminv1.Tenant_STATE_ACTIVE {
		t.Fatalf("tenant = %+v", created.Msg.GetTenant())
	}
	got, err := h.svc.GetTenant(ctx, request(h, &adminv1.GetTenantRequest{Id: id}))
	if err != nil || got.Msg.GetTenant().GetDisplayName() != "Ministry" {
		t.Fatalf("GetTenant = %+v, %v", got.Msg, err)
	}
	updated, err := h.svc.UpdateTenant(ctx, request(h, &adminv1.UpdateTenantRequest{
		Id: id, DisplayName: "Health", State: adminv1.Tenant_STATE_SUSPENDED,
	}))
	if err != nil || updated.Msg.GetTenant().GetState() != adminv1.Tenant_STATE_SUSPENDED {
		t.Fatalf("UpdateTenant = %+v, %v", updated.Msg, err)
	}
	list, err := h.svc.ListTenants(ctx, request(h, &adminv1.ListTenantsRequest{}))
	if err != nil || len(list.Msg.GetTenants()) != 2 {
		t.Fatalf("ListTenants = %d, %v", len(list.Msg.GetTenants()), err)
	}
	if _, serr := h.svc.DeleteTenant(ctx, request(h, &adminv1.DeleteTenantRequest{Id: id})); serr != nil {
		t.Fatalf("DeleteTenant: %v", serr)
	}
	page, err := h.log.Query(ctx, auditlog.Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if page.TotalSize < 5 {
		t.Fatalf("audit records = %d", page.TotalSize)
	}
	for _, r := range page.Records {
		if r.Actor == "" || r.Action == "" {
			t.Fatalf("record = %+v", r)
		}
	}
}

func TestTenantRPCsReportBadInput(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("CreateTenant = %v", err)
	}
	if _, err := h.svc.GetTenant(ctx, request(h, &adminv1.GetTenantRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("GetTenant = %v", err)
	}
	if _, err := h.svc.UpdateTenant(ctx, request(h, &adminv1.UpdateTenantRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("UpdateTenant = %v", err)
	}
	if _, err := h.svc.DeleteTenant(ctx, request(h, &adminv1.DeleteTenantRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("DeleteTenant = %v", err)
	}
}

func TestListTenantsPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{DisplayName: "T"})); err != nil {
			t.Fatalf("CreateTenant: %v", err)
		}
	}
	seen := 0
	token := ""
	for round := 0; round < 10; round++ {
		res, err := h.svc.ListTenants(ctx, request(h, &adminv1.ListTenantsRequest{
			Page: &commonv1.Pagination{PageSize: 2, PageToken: token},
		}))
		if err != nil {
			t.Fatalf("ListTenants: %v", err)
		}
		seen += len(res.Msg.GetTenants())
		token = res.Msg.GetPage().GetNextPageToken()
		if token == "" {
			break
		}
	}
	if seen != 5 {
		t.Fatalf("saw %d tenants", seen)
	}
	res, err := h.svc.ListTenants(ctx, request(h, &adminv1.ListTenantsRequest{
		Page: &commonv1.Pagination{PageToken: "nothing"},
	}))
	if err != nil || len(res.Msg.GetTenants()) != 0 {
		t.Fatalf("unknown token = %+v, %v", res.Msg, err)
	}
}

func TestTrustRPCsForwardToTheRegistry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	entry := &trustv1.TrustEntry{
		Identifier:  &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:issuer.example"}},
		DisplayName: "Issuer", Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_ACTIVE,
	}
	if _, err := h.svc.UpsertTrustEntry(ctx, request(h, &adminv1.UpsertTrustEntryRequest{Entry: entry})); err != nil {
		t.Fatalf("UpsertTrustEntry: %v", err)
	}
	got, err := h.svc.GetTrustEntry(ctx, request(h, &adminv1.GetTrustEntryRequest{Identifier: entry.GetIdentifier()}))
	if err != nil || got.Msg.GetEntry().GetDisplayName() != "Issuer" {
		t.Fatalf("GetTrustEntry = %+v, %v", got.Msg, err)
	}
	list, err := h.svc.ListTrustEntries(ctx, request(h, &adminv1.ListTrustEntriesRequest{Role: commonv1.Role_ROLE_ISSUER}))
	if err != nil || len(list.Msg.GetEntries()) != 1 {
		t.Fatalf("ListTrustEntries = %+v, %v", list.Msg, err)
	}
	if _, err := h.svc.DeleteTrustEntry(ctx, request(h, &adminv1.DeleteTrustEntryRequest{Identifier: entry.GetIdentifier()})); err != nil {
		t.Fatalf("DeleteTrustEntry: %v", err)
	}
	if _, err := h.svc.GetTrustEntry(ctx, request(h, &adminv1.GetTrustEntryRequest{Identifier: entry.GetIdentifier()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetTrustEntry after delete = %v", err)
	}
	h.trust.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if _, err := h.svc.UpsertTrustEntry(ctx, request(h, &adminv1.UpsertTrustEntryRequest{Entry: entry})); err == nil {
		t.Error("UpsertTrustEntry hid a registry error")
	}
}

func TestTrustRPCsNeedARegistry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc, err := service.New(service.Deps{
		Cfg: h.cfg, Records: h.rec, Audit: h.log, Login: h.login, Providers: h.svc.Providers(),
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	header := h.call(nil)
	cases := map[string]func() error{
		"upsert": func() error {
			req := connect.NewRequest(&adminv1.UpsertTrustEntryRequest{})
			req.Header().Set("Authorization", header.Get("Authorization"))
			_, err := svc.UpsertTrustEntry(ctx, req)
			return err
		},
		"get": func() error {
			req := connect.NewRequest(&adminv1.GetTrustEntryRequest{})
			req.Header().Set("Authorization", header.Get("Authorization"))
			_, err := svc.GetTrustEntry(ctx, req)
			return err
		},
		"list": func() error {
			req := connect.NewRequest(&adminv1.ListTrustEntriesRequest{})
			req.Header().Set("Authorization", header.Get("Authorization"))
			_, err := svc.ListTrustEntries(ctx, req)
			return err
		},
		"delete": func() error {
			req := connect.NewRequest(&adminv1.DeleteTrustEntryRequest{})
			req.Header().Set("Authorization", header.Get("Authorization"))
			_, err := svc.DeleteTrustEntry(ctx, req)
			return err
		},
		"approve": func() error {
			req := connect.NewRequest(&adminv1.ApproveTrustEntryRequest{})
			req.Header().Set("Authorization", header.Get("Authorization"))
			_, err := svc.ApproveTrustEntry(ctx, req)
			return err
		},
		"reject": func() error {
			req := connect.NewRequest(&adminv1.RejectTrustEntryRequest{})
			req.Header().Set("Authorization", header.Get("Authorization"))
			_, err := svc.RejectTrustEntry(ctx, req)
			return err
		},
	}
	for name, run := range cases {
		if code := connect.CodeOf(run()); code != connect.CodeFailedPrecondition {
			t.Errorf("%s = %v", name, code)
		}
	}
}

func TestAuthProviderRPCsWithDynamicRegistration(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created, err := h.svc.CreateAuthProvider(ctx, request(h, &adminv1.CreateAuthProviderRequest{
		Provider: &adminv1.AuthProvider{
			DisplayName: "Keycloak", DiscoveryUrl: h.idpSrv.URL + "/.well-known/openid-configuration",
			RolesClaimPath: "realm_access.roles", Enabled: true,
			Roles: []commonv1.Role{commonv1.Role_ROLE_ADMIN},
		},
		DynamicRegistration: true,
	}))
	if err != nil {
		t.Fatalf("CreateAuthProvider: %v", err)
	}
	p := created.Msg.GetProvider()
	if p.GetClientId() != "registered" || p.GetId() == "" {
		t.Fatalf("provider = %+v", p)
	}
	if p.GetClientSecret().GetName() == "" {
		t.Fatalf("the provider record has no secret reference")
	}
	got, err := h.svc.GetAuthProvider(ctx, request(h, &adminv1.GetAuthProviderRequest{Id: p.GetId()}))
	if err != nil || got.Msg.GetProvider().GetDisplayName() != "Keycloak" {
		t.Fatalf("GetAuthProvider = %+v, %v", got.Msg, err)
	}
	updated, err := h.svc.UpdateAuthProvider(ctx, request(h, &adminv1.UpdateAuthProviderRequest{
		Provider: &adminv1.AuthProvider{Id: p.GetId(), DisplayName: "Renamed", Enabled: false},
	}))
	if err != nil {
		t.Fatalf("UpdateAuthProvider: %v", err)
	}
	if updated.Msg.GetProvider().GetDisplayName() != "Renamed" || updated.Msg.GetProvider().GetEnabled() {
		t.Fatalf("updated = %+v", updated.Msg.GetProvider())
	}
	if updated.Msg.GetProvider().GetClientId() != "registered" {
		t.Errorf("the update lost the client id")
	}
	list, err := h.svc.ListAuthProviders(ctx, request(h, &adminv1.ListAuthProvidersRequest{}))
	if err != nil || len(list.Msg.GetProviders()) != 2 {
		t.Fatalf("ListAuthProviders = %d, %v", len(list.Msg.GetProviders()), err)
	}
	if _, err := h.svc.DeleteAuthProvider(ctx, request(h, &adminv1.DeleteAuthProviderRequest{Id: p.GetId()})); err != nil {
		t.Fatalf("DeleteAuthProvider: %v", err)
	}
	if _, err := h.svc.GetAuthProvider(ctx, request(h, &adminv1.GetAuthProviderRequest{Id: p.GetId()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetAuthProvider after delete = %v", err)
	}
}

// TestCreateAuthProviderStoresKindAndStacks is ADR-035 decision 2: the
// record keeps its kind, realm, registration mode, console, stacks,
// token authentication method, key reference, and default flag.
func TestCreateAuthProviderStoresKindAndStacks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	in := &adminv1.AuthProvider{
		DisplayName: "National IdP", DiscoveryUrl: h.idp.DiscoveryURL(), ClientId: "vca-admin",
		Roles: []commonv1.Role{commonv1.Role_ROLE_ADMIN, commonv1.Role_ROLE_ISSUER}, Enabled: true,
		Kind:            adminv1.ProviderKind_PROVIDER_KIND_ESIGNET,
		Realm:           "national",
		Registration:    adminv1.Registration_REGISTRATION_NONE,
		ConsoleUrl:      "https://idp.example/console/",
		Stacks:          []configv1.Dpg{configv1.Dpg_DPG_INJI, configv1.Dpg_DPG_CREDEBL},
		TokenAuthMethod: adminv1.TokenAuth_TOKEN_AUTH_PRIVATE_KEY_JWT,
		PrivateKey:      &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_FILE, Name: "/run/secrets/esignet.pem"},
		IsDefault:       true,
	}
	created, err := h.svc.CreateAuthProvider(ctx, request(h, &adminv1.CreateAuthProviderRequest{Provider: in}))
	if err != nil {
		t.Fatalf("CreateAuthProvider: %v", err)
	}
	got, err := h.svc.GetAuthProvider(ctx, request(h, &adminv1.GetAuthProviderRequest{Id: created.Msg.GetProvider().GetId()}))
	if err != nil {
		t.Fatalf("GetAuthProvider: %v", err)
	}
	p := got.Msg.GetProvider()
	if p.GetKind() != in.GetKind() || p.GetRealm() != "national" || p.GetRegistration() != in.GetRegistration() ||
		p.GetConsoleUrl() != in.GetConsoleUrl() || len(p.GetStacks()) != 2 || p.GetStacks()[1] != configv1.Dpg_DPG_CREDEBL ||
		p.GetTokenAuthMethod() != in.GetTokenAuthMethod() || p.GetPrivateKey().GetName() != "/run/secrets/esignet.pem" ||
		!p.GetIsDefault() {
		t.Errorf("stored = %+v", p)
	}
	// An update keeps the profile when the caller sends the record back
	// with one change, and takes a new profile when the caller sends one.
	p.DisplayName = "Renamed"
	updated, err := h.svc.UpdateAuthProvider(ctx, request(h, &adminv1.UpdateAuthProviderRequest{Provider: p}))
	if err != nil {
		t.Fatalf("UpdateAuthProvider: %v", err)
	}
	if updated.Msg.GetProvider().GetKind() != in.GetKind() || len(updated.Msg.GetProvider().GetStacks()) != 2 {
		t.Errorf("the update lost the profile: %+v", updated.Msg.GetProvider())
	}
	// private_key_jwt without a key is a bad request.
	bad := &adminv1.AuthProvider{
		DisplayName: "Bad", DiscoveryUrl: h.idp.DiscoveryURL(), ClientId: "c", Enabled: true,
		TokenAuthMethod: adminv1.TokenAuth_TOKEN_AUTH_PRIVATE_KEY_JWT,
	}
	if _, err := h.svc.CreateAuthProvider(ctx, request(h, &adminv1.CreateAuthProviderRequest{Provider: bad})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("private_key_jwt with no key = %v", err)
	}
}

func TestCreateAuthProviderReportsBadInput(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.CreateAuthProvider(ctx, request(h, &adminv1.CreateAuthProviderRequest{
		Provider: &adminv1.AuthProvider{DiscoveryUrl: "nowhere"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("bad discovery url = %v", err)
	}
	if _, err := h.svc.CreateAuthProvider(ctx, request(h, &adminv1.CreateAuthProviderRequest{
		Provider: &adminv1.AuthProvider{DiscoveryUrl: h.idp.DiscoveryURL()}, DynamicRegistration: true,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("no registration endpoint = %v", err)
	}
	if _, err := h.svc.UpdateAuthProvider(ctx, request(h, &adminv1.UpdateAuthProviderRequest{
		Provider: &adminv1.AuthProvider{Id: "missing"},
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("unknown provider = %v", err)
	}
	if _, err := h.svc.DeleteAuthProvider(ctx, request(h, &adminv1.DeleteAuthProviderRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("delete unknown = %v", err)
	}
}

func TestAPIKeyRPCs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created, err := h.svc.CreateApiKey(ctx, request(h, &adminv1.CreateApiKeyRequest{
		DisplayName: "CI", TenantId: h.tenantID,
		Roles:     []commonv1.Role{commonv1.Role_ROLE_ISSUER},
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}))
	if err != nil {
		t.Fatalf("CreateApiKey: %v", err)
	}
	if created.Msg.GetSecret() == "" || created.Msg.GetKey().GetPrefix() == "" {
		t.Fatalf("key = %+v", created.Msg)
	}
	if created.Msg.GetKey().GetExpiresAt() == nil {
		t.Error("the key has no expiry")
	}
	list, err := h.svc.ListApiKeys(ctx, request(h, &adminv1.ListApiKeysRequest{TenantId: h.tenantID}))
	if err != nil || len(list.Msg.GetKeys()) != 2 {
		t.Fatalf("ListApiKeys = %d, %v", len(list.Msg.GetKeys()), err)
	}
	for _, k := range list.Msg.GetKeys() {
		if k.GetPrefix() == "" {
			t.Error("a key has no prefix")
		}
	}
	if _, err := h.svc.RevokeApiKey(ctx, request(h, &adminv1.RevokeApiKeyRequest{Id: created.Msg.GetKey().GetId()})); err != nil {
		t.Fatalf("RevokeApiKey: %v", err)
	}
	if _, err := h.svc.RevokeApiKey(ctx, request(h, &adminv1.RevokeApiKeyRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("revoke unknown = %v", err)
	}
	if _, err := h.svc.CreateApiKey(ctx, request(h, &adminv1.CreateApiKeyRequest{TenantId: h.tenantID})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("empty key = %v", err)
	}
}

func TestGetServiceHealthProbesEveryService(t *testing.T) {
	h := newHarness(t)
	res, err := h.svc.GetServiceHealth(context.Background(), request(h, &adminv1.GetServiceHealthRequest{}))
	if err != nil {
		t.Fatalf("GetServiceHealth: %v", err)
	}
	services := res.Msg.GetServices()
	if len(services) != 1 || !services[0].GetReady() {
		t.Fatalf("services = %+v", services)
	}
	if services[0].GetName() != "trust-registry" || services[0].GetVersion() != "1.0.0" {
		t.Fatalf("service = %+v", services[0])
	}
	if services[0].GetCheckedAt() == nil {
		t.Error("the probe has no time")
	}
}

func TestQueryAuditLogFilters(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{DisplayName: "One"})); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	res, err := h.svc.QueryAuditLog(ctx, request(h, &adminv1.QueryAuditLogRequest{
		Action: "admin.CreateTenant",
		From:   timestamppb.New(time.Now().Add(-time.Hour)),
		To:     timestamppb.New(time.Now().Add(time.Hour)),
		Page:   &commonv1.Pagination{PageSize: 10},
	}))
	if err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	if len(res.Msg.GetRecords()) != 1 {
		t.Fatalf("records = %+v", res.Msg.GetRecords())
	}
	rec := res.Msg.GetRecords()[0]
	if rec.GetAction() != "admin.CreateTenant" || !rec.GetOk() || rec.GetId() == "" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestOnboardAdminNeedsNoSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := records.NewBootstrapToken()
	if err := h.rec.SetBootstrap(ctx, token); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	res, err := h.svc.OnboardAdmin(ctx, connect.NewRequest(&adminv1.OnboardAdminRequest{
		BootstrapToken: token, IdToken: h.idp.IDToken(h.idp.ClientID, ""), ProviderId: "idp",
	}))
	if err != nil {
		t.Fatalf("OnboardAdmin: %v", err)
	}
	if res.Msg.GetSubject() != h.idp.Subject {
		t.Fatalf("response = %+v", res.Msg)
	}
	if _, err := h.svc.OnboardAdmin(ctx, connect.NewRequest(&adminv1.OnboardAdminRequest{
		BootstrapToken: token, IdToken: h.idp.IDToken(h.idp.ClientID, ""), ProviderId: "idp",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("second onboarding = %v", err)
	}
	if _, err := h.svc.OnboardAdmin(ctx, connect.NewRequest(&adminv1.OnboardAdminRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("empty request = %v", err)
	}
}

func TestOnboardAdminRefusesAWrongToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.rec.SetBootstrap(ctx, records.NewBootstrapToken()); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	_, err := h.svc.OnboardAdmin(ctx, connect.NewRequest(&adminv1.OnboardAdminRequest{
		BootstrapToken: "wrong-token-value", IdToken: h.idp.IDToken(h.idp.ClientID, ""), ProviderId: "idp",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("OnboardAdmin = %v", err)
	}
}

func TestListCommandsCarriesTheProtoHelpText(t *testing.T) {
	h := newHarness(t)
	res, err := h.svc.ListCommands(context.Background(), connect.NewRequest(&adminv1.ListCommandsRequest{}))
	if err != nil {
		t.Fatalf("ListCommands: %v", err)
	}
	commands := res.Msg.GetCommands()
	if len(commands) < 15 {
		t.Fatalf("commands = %d", len(commands))
	}
	for _, c := range commands {
		if c.GetPath() == "" || c.GetSummary() == "" || c.GetDescription() == "" || c.GetRpc() == "" {
			t.Fatalf("command = %+v", c)
		}
	}
	if commands[0].GetSummary() != "Creates one tenant." {
		t.Fatalf("first summary = %q", commands[0].GetSummary())
	}
}

func TestReadyReportsTheStore(t *testing.T) {
	h := newHarness(t)
	if !h.svc.Ready() {
		t.Fatal("the service is not ready")
	}
}

func TestRoleNamesAndValuesRoundTrip(t *testing.T) {
	for _, r := range []commonv1.Role{
		commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER,
		commonv1.Role_ROLE_VERIFIER, commonv1.Role_ROLE_ADMIN,
	} {
		if service.RoleValue(service.RoleName(r)) != r {
			t.Errorf("role %v did not round trip", r)
		}
	}
	if service.RoleName(commonv1.Role_ROLE_UNSPECIFIED) != "" {
		t.Error("an unspecified role has a name")
	}
	if service.RoleValue("nothing") != commonv1.Role_ROLE_UNSPECIFIED {
		t.Error("an unknown name has a role")
	}
}

func TestOnboardProviderDelegatesToTheOnboardingPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	resp, err := h.svc.OnboardProvider(ctx, request(h, &adminv1.OnboardProviderRequest{
		IssuerUrl:           h.idpSrv.URL,
		DynamicRegistration: true,
	}))
	if err != nil {
		t.Fatalf("OnboardProvider: %v", err)
	}
	p := resp.Msg.GetProvider()
	if p.GetId() == "" || p.GetClientId() != "registered" || !p.GetEnabled() {
		t.Fatalf("provider = %+v", p)
	}
	got, err := h.svc.GetAuthProvider(ctx, request(h, &adminv1.GetAuthProviderRequest{Id: p.GetId()}))
	if err != nil || got.Msg.GetProvider().GetId() != p.GetId() {
		t.Fatalf("GetAuthProvider = %+v, %v", got.Msg, err)
	}
	if _, err := h.svc.OnboardProvider(ctx, request(h, &adminv1.OnboardProviderRequest{
		IssuerUrl: "nowhere",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a bad issuer URL = %v", err)
	}
}

// pairAuth is one fake auth service of a live pair: the provider RPCs
// over a registry that accepts the admin session token.
type pairAuth struct {
	registry *oidcflow.Registry
	server   *httptest.Server
}

func newPairAuth(t *testing.T, h *harness, role string) *pairAuth {
	t.Helper()
	registry, err := oidcflow.NewRegistry(oidcflow.NewMemoryPersister(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The pair accepts what the admin key set signed, as an auth service
	// with VCA_<ROLE>_AUTH_ADMIN_JWKS_URL does.
	accept := func(_ context.Context, hdr http.Header) error {
		_, verr := h.login.Signer().Verify(oidcflow.TokenFromRequest(&http.Request{Header: hdr}, ""))
		return verr
	}
	mux := http.NewServeMux()
	mux.Handle(oidcflow.NewAdminHandler(oidcflow.AdminProviders{Registry: registry, Authorize: accept, Roles: []string{role}}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &pairAuth{registry: registry, server: srv}
}

// withFanOut rebuilds the service of the harness with a fan out over a
// snapshot of one live issuer pair and one live holder pair.
func withFanOut(t *testing.T, h *harness) (*pairAuth, *pairAuth) {
	t.Helper()
	issuer := newPairAuth(t, h, "issuer")
	holder := newPairAuth(t, h, "holder")
	snap := topology.Snapshot{Peers: []topology.Status{
		{Peer: topology.Peer{Pair: "issuer-waltid", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID,
			Services: map[string]string{"issuer-auth": issuer.server.URL}}, State: topology.Live},
		{Peer: topology.Peer{Pair: "holder-waltid", Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID,
			Services: map[string]string{"wallet-auth": holder.server.URL}}, State: topology.Live},
		{Peer: topology.Peer{Pair: "issuer-inji", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}, State: topology.Absent},
	}}
	push, err := fanout.New(fanout.Options{Snapshot: func(context.Context) topology.Snapshot { return snap }})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Deps{
		Cfg: h.cfg, Records: h.rec, Audit: h.log, Login: h.login, Providers: h.svc.Providers(),
		Vault: onboard.NewVault(""), Fetch: http.DefaultClient, Trust: h.trust,
		Health: health.New(nil, time.Second, nil), FanOut: push,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return issuer, holder
}

// session mints an admin session token like a browser login would.
func (h *harness) session(t *testing.T) string {
	t.Helper()
	token, _, err := h.login.Signer().Issue(oidcflow.Claims{Subject: "kc|root", Roles: []string{login.RoleSuperAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// TestCreateAuthProviderPushesToTheLivePairs is ADR-035 decision 5: a
// provider created with an admin session reaches the auth service of
// every live pair its roles and stacks name, and the audit log holds
// one record per target.
func TestCreateAuthProviderPushesToTheLivePairs(t *testing.T) {
	h := newHarness(t)
	issuer, holder := withFanOut(t, h)
	ctx := context.Background()
	in := &adminv1.AuthProvider{
		DisplayName: "National IdP", DiscoveryUrl: h.idp.DiscoveryURL(), ClientId: "vca", Enabled: true,
		Roles:  []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER},
		Stacks: []configv1.Dpg{configv1.Dpg_DPG_WALTID, configv1.Dpg_DPG_INJI},
	}
	req := connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: in})
	req.Header().Set("Authorization", "Bearer "+h.session(t))
	created, err := h.svc.CreateAuthProvider(ctx, req)
	if err != nil {
		t.Fatalf("CreateAuthProvider: %v", err)
	}
	for name, pair := range map[string]*pairAuth{"issuer-waltid": issuer, "holder-waltid": holder} {
		list := pair.registry.List()
		if len(list) != 1 || list[0].ClientID != "vca" || list[0].DisplayName != "National IdP" {
			t.Fatalf("%s holds %+v", name, list)
		}
	}
	page, err := h.log.Query(ctx, auditlog.Filter{Action: "admin.PushAuthProvider"})
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalSize != 2 || !page.Records[0].OK || !page.Records[1].OK {
		t.Fatalf("audit %+v", page.Records)
	}
	if got := page.Records[0].Target; got != "issuer-waltid "+created.Msg.GetProvider().GetId() && got != "holder-waltid "+created.Msg.GetProvider().GetId() {
		t.Fatalf("audit target %q", got)
	}
	// The answer carries the report: one result per target, in target
	// order, so a client can show one line per pair.
	pushes := created.Msg.GetPushes()
	if len(pushes) != 2 || pushes[0].GetPair() != "issuer-waltid" || pushes[1].GetPair() != "holder-waltid" {
		t.Fatalf("pushes %+v", pushes)
	}
	for _, push := range pushes {
		if !push.GetOk() || !push.GetCreated() || push.GetError() != "" {
			t.Errorf("push %+v, want ok and created", push)
		}
	}
	// An update with a session pushes again without a duplicate.
	p := created.Msg.GetProvider()
	p.DisplayName = "Renamed"
	upd := connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: p})
	upd.Header().Set("Authorization", "Bearer "+h.session(t))
	updated, uerr := h.svc.UpdateAuthProvider(ctx, upd)
	if uerr != nil {
		t.Fatalf("UpdateAuthProvider: %v", uerr)
	}
	if pushes := updated.Msg.GetPushes(); len(pushes) != 2 || pushes[0].GetCreated() || !pushes[0].GetOk() {
		t.Fatalf("update pushes %+v, want two updates", pushes)
	}
	if list := issuer.registry.List(); len(list) != 1 || list[0].DisplayName != "Renamed" {
		t.Fatalf("issuer-waltid after the update holds %+v", list)
	}
	// An API key opens the RPC, but there is no session to forward, so
	// the push fails at every target and the audit log says so.
	in.ClientId = "vca-2"
	byKey, kerr := h.svc.CreateAuthProvider(ctx, request(h, &adminv1.CreateAuthProviderRequest{Provider: in}))
	if kerr != nil {
		t.Fatalf("CreateAuthProvider with a key: %v", kerr)
	}
	if pushes := byKey.Msg.GetPushes(); len(pushes) != 2 || pushes[0].GetOk() || pushes[0].GetError() == "" {
		t.Fatalf("key pushes %+v, want two failures with a reason", pushes)
	}
	page, err = h.log.Query(ctx, auditlog.Filter{Action: "admin.PushAuthProvider"})
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, r := range page.Records {
		if !r.OK {
			failed++
		}
	}
	if page.TotalSize != 6 || failed != 2 {
		t.Fatalf("audit after the key call: %d records, %d failed", page.TotalSize, failed)
	}
	if list := issuer.registry.List(); len(list) != 1 {
		t.Fatalf("the key call reached issuer-waltid: %+v", list)
	}
}

// pendingEntry is an issuer that asked for trust and waits for review.
func pendingEntry(did string) *trustv1.TrustEntry {
	return &trustv1.TrustEntry{
		Identifier:  &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: did}},
		DisplayName: "Pending issuer", Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_PENDING,
	}
}

// auditActions returns the actions and outcomes of the audit log.
func auditActions(t *testing.T, h *harness, action string) []auditlog.Record {
	t.Helper()
	page, err := h.log.Query(context.Background(), auditlog.Filter{Action: action})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	return page.Records
}

func TestApproveTrustEntrySetsActiveAndWritesAudit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	e := pendingEntry("did:web:pending.example")
	h.trust.entries[key(e.GetIdentifier())] = e
	res, err := h.svc.ApproveTrustEntry(ctx, request(h, &adminv1.ApproveTrustEntryRequest{Identifier: e.GetIdentifier()}))
	if err != nil {
		t.Fatalf("ApproveTrustEntry: %v", err)
	}
	if res.Msg.GetEntry().GetStatus() != trustv1.Status_STATUS_ACTIVE ||
		h.trust.entries["did:web:pending.example"].GetStatus() != trustv1.Status_STATUS_ACTIVE {
		t.Fatalf("the entry is %v, want active", res.Msg.GetEntry().GetStatus())
	}
	recs := auditActions(t, h, "admin.ApproveTrustEntry")
	if len(recs) != 1 || !recs[0].OK || recs[0].Target != "did:web:pending.example" {
		t.Fatalf("audit = %+v", recs)
	}
	// An active entry is not pending, so a second approval fails and
	// the audit log records the refusal.
	if _, err := h.svc.ApproveTrustEntry(ctx, request(h, &adminv1.ApproveTrustEntryRequest{Identifier: e.GetIdentifier()})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a second approval = %v, want failed precondition", err)
	}
	if recs := auditActions(t, h, "admin.ApproveTrustEntry"); len(recs) != 2 {
		t.Fatalf("audit after the refusal = %d records", len(recs))
	}
}

func TestRejectTrustEntryRemovesAndWritesAudit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	e := pendingEntry("did:web:reject.example")
	h.trust.entries[key(e.GetIdentifier())] = e
	if _, err := h.svc.RejectTrustEntry(ctx, request(h, &adminv1.RejectTrustEntryRequest{Identifier: e.GetIdentifier()})); err != nil {
		t.Fatalf("RejectTrustEntry: %v", err)
	}
	if _, ok := h.trust.entries["did:web:reject.example"]; ok {
		t.Fatal("the rejected entry is still in the registry")
	}
	recs := auditActions(t, h, "admin.RejectTrustEntry")
	if len(recs) != 1 || !recs[0].OK || recs[0].Target != "did:web:reject.example" {
		t.Fatalf("audit = %+v", recs)
	}
	// An unknown entry is not found. An active entry cannot be rejected.
	if _, err := h.svc.RejectTrustEntry(ctx, request(h, &adminv1.RejectTrustEntryRequest{Identifier: e.GetIdentifier()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("an unknown entry = %v, want not found", err)
	}
	active := pendingEntry("did:web:active.example")
	active.Status = trustv1.Status_STATUS_ACTIVE
	h.trust.entries[key(active.GetIdentifier())] = active
	if _, err := h.svc.RejectTrustEntry(ctx, request(h, &adminv1.RejectTrustEntryRequest{Identifier: active.GetIdentifier()})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("an active entry = %v, want failed precondition", err)
	}
	if _, ok := h.trust.entries["did:web:active.example"]; !ok {
		t.Fatal("the refused rejection removed an active entry")
	}
}

func TestListTrustEntriesForwardsTheStatusFilter(t *testing.T) {
	h := newHarness(t)
	e := pendingEntry("did:web:pending.example")
	h.trust.entries[key(e.GetIdentifier())] = e
	active := pendingEntry("did:web:active.example")
	active.Status = trustv1.Status_STATUS_ACTIVE
	h.trust.entries[key(active.GetIdentifier())] = active
	res, err := h.svc.ListTrustEntries(context.Background(), request(h, &adminv1.ListTrustEntriesRequest{Status: trustv1.Status_STATUS_PENDING}))
	if err != nil || len(res.Msg.GetEntries()) != 1 || res.Msg.GetEntries()[0].GetStatus() != trustv1.Status_STATUS_PENDING {
		t.Fatalf("ListTrustEntries = %+v, %v", res, err)
	}
}

// TestTrustRegistryRPCsForwardAndAudit forwards the four registry RPCs
// to the trust registry and writes one audit record for each change.
func TestTrustRegistryRPCsForwardAndAudit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	reg := &trustv1.Registry{
		Name: "Kenya trust registry", Method: trustv1.RegistryMethod_REGISTRY_METHOD_DEDI, Url: "https://trust.go.ke",
		Anchor: &trustv1.Registry_Anchor{Anchor: &trustv1.Registry_Anchor_JwksUrl{JwksUrl: "https://trust.go.ke/jwks.json"}},
	}
	added, err := h.svc.AddTrustRegistry(ctx, request(h, &adminv1.AddTrustRegistryRequest{Registry: reg}))
	if err != nil || added.Msg.GetRegistry().GetId() != "reg-1" {
		t.Fatalf("AddTrustRegistry = %+v, %v", added, err)
	}
	list, err := h.svc.ListTrustRegistries(ctx, request(h, &adminv1.ListTrustRegistriesRequest{}))
	if err != nil || len(list.Msg.GetRegistries()) != 1 || list.Msg.GetJwksUrl() == "" {
		t.Fatalf("ListTrustRegistries = %+v, %v", list, err)
	}
	if _, err := h.svc.SyncTrustRegistry(ctx, request(h, &adminv1.SyncTrustRegistryRequest{Id: "reg-1"})); err != nil {
		t.Fatalf("SyncTrustRegistry: %v", err)
	}
	if _, err := h.svc.RemoveTrustRegistry(ctx, request(h, &adminv1.RemoveTrustRegistryRequest{Id: "reg-1"})); err != nil {
		t.Fatalf("RemoveTrustRegistry: %v", err)
	}
	if _, err := h.svc.RemoveTrustRegistry(ctx, request(h, &adminv1.RemoveTrustRegistryRequest{Id: "reg-1"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a second remove = %v", err)
	}
	if _, err := h.svc.SyncTrustRegistry(ctx, request(h, &adminv1.SyncTrustRegistryRequest{Id: "reg-1"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("sync of a removed registry = %v", err)
	}
	for action, n := range map[string]int{"admin.AddTrustRegistry": 1, "admin.SyncTrustRegistry": 2, "admin.RemoveTrustRegistry": 2} {
		recs := auditActions(t, h, action)
		if len(recs) != n {
			t.Errorf("%s has %d audit records, want %d", action, len(recs), n)
		}
	}
	if recs := auditActions(t, h, "admin.AddTrustRegistry"); recs[0].Target != "reg-1" {
		t.Errorf("the add record names %q", recs[0].Target)
	}
	h.trust.err = errors.New("registry down")
	if _, err := h.svc.AddTrustRegistry(ctx, request(h, &adminv1.AddTrustRegistryRequest{Registry: reg})); err == nil {
		t.Error("AddTrustRegistry hid a registry error")
	}
	for _, rpc := range []func() error{
		func() error {
			_, err := h.svc.AddTrustRegistry(ctx, connect.NewRequest(&adminv1.AddTrustRegistryRequest{}))
			return err
		},
		func() error {
			_, err := h.svc.ListTrustRegistries(ctx, connect.NewRequest(&adminv1.ListTrustRegistriesRequest{}))
			return err
		},
		func() error {
			_, err := h.svc.RemoveTrustRegistry(ctx, connect.NewRequest(&adminv1.RemoveTrustRegistryRequest{}))
			return err
		},
		func() error {
			_, err := h.svc.SyncTrustRegistry(ctx, connect.NewRequest(&adminv1.SyncTrustRegistryRequest{}))
			return err
		},
	} {
		if rpc() == nil {
			t.Error("a registry RPC accepted an anonymous caller")
		}
	}
}

func TestTrustRegistryRPCsNeedARegistry(t *testing.T) {
	h := newHarness(t)
	svc, err := service.New(service.Deps{Cfg: h.cfg, Records: h.rec, Audit: h.log, Login: h.login, Providers: h.svc.Providers()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := svc.AddTrustRegistry(ctx, request(h, &adminv1.AddTrustRegistryRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("add = %v", err)
	}
	if _, err := svc.ListTrustRegistries(ctx, request(h, &adminv1.ListTrustRegistriesRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("list = %v", err)
	}
	if _, err := svc.RemoveTrustRegistry(ctx, request(h, &adminv1.RemoveTrustRegistryRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("remove = %v", err)
	}
	if _, err := svc.SyncTrustRegistry(ctx, request(h, &adminv1.SyncTrustRegistryRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("sync = %v", err)
	}
}

// TestTrustChangesNameTheAdmin sends the actor of each trust change to
// the registry, so the audit log of the registry names the admin too
// (ADR-039 decision 1).
func TestTrustChangesNameTheAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	entry := &trustv1.TrustEntry{
		Identifier:  &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:issuer.example"}},
		DisplayName: "Issuer", Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_PENDING,
	}
	if _, err := h.svc.UpsertTrustEntry(ctx, request(h, &adminv1.UpsertTrustEntryRequest{Entry: entry})); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.ApproveTrustEntry(ctx, request(h, &adminv1.ApproveTrustEntryRequest{Identifier: entry.GetIdentifier()})); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.DeleteTrustEntry(ctx, request(h, &adminv1.DeleteTrustEntryRequest{Identifier: entry.GetIdentifier()})); err != nil {
		t.Fatal(err)
	}
	actions := auditActions(t, h, "admin.UpsertTrustEntry")
	if len(actions) != 1 || actions[0].Actor == "" {
		t.Fatalf("admin records = %+v", actions)
	}
	if len(h.trust.actors) != 3 {
		t.Fatalf("actors = %q", h.trust.actors)
	}
	for _, a := range h.trust.actors {
		if a != actions[0].Actor {
			t.Errorf("actor %q, want %q", a, actions[0].Actor)
		}
	}
}
