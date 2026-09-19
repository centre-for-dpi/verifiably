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
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/audit"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/health"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The service must satisfy the generated handler interface.
var _ adminv1connect.AdminServiceHandler = (*service.Service)(nil)

// fakeTrust is a trust registry client in process.
type fakeTrust struct {
	trustv1connect.TrustServiceClient
	entries map[string]*trustv1.TrustEntry
	err     error
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

func (f *fakeTrust) ListEntries(_ context.Context, _ *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	res := &trustv1.ListEntriesResponse{Page: &commonv1.PageResult{TotalSize: int64(len(f.entries))}}
	for _, e := range f.entries {
		res.Entries = append(res.Entries, e)
	}
	return connect.NewResponse(res), nil
}

func (f *fakeTrust) DeleteEntry(_ context.Context, req *connect.Request[trustv1.DeleteEntryRequest]) (*connect.Response[trustv1.DeleteEntryResponse], error) {
	delete(f.entries, key(req.Msg.GetIdentifier()))
	return connect.NewResponse(&trustv1.DeleteEntryResponse{}), nil
}

// harness holds the service and the values a test needs.
type harness struct {
	svc      *service.Service
	rec      *records.Store
	log      *audit.Log
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
		_, _ = w.Write([]byte("ready"))
	}))
	t.Cleanup(h.health.Close)
	kv := store.Memory()
	rec, err := records.New(kv, nil)
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	log, err := audit.New(kv, nil)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	registry, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := registry.Put(oidcflow.Provider{
		ID: "idp", DisplayName: "Test IdP", DiscoveryURL: h.idp.DiscoveryURL(),
		ClientID: h.idp.ClientID, Enabled: true,
	}); err != nil {
		t.Fatalf("Put: %v", err)
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
	_ = json.NewEncoder(w).Encode(v)
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
	if _, err := h.svc.DeleteTenant(ctx, request(h, &adminv1.DeleteTenantRequest{Id: id})); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	page, err := h.log.Query(ctx, audit.Filter{})
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
