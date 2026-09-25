// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/trustsnap"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/federation"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// external serves a signed ETSI list with one issuer and its JWKS.
func external(t *testing.T) (*httptest.Server, keys.Key) {
	t.Helper()
	docs := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	k, err := keys.Generate(jose.ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keys.NewRing(k)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := etsi.Publisher{}.Publish(publish.Input{
		Entries: []entry.Entry{
			{DID: "did:web:registrar.go.ke", DisplayName: "National Registration Bureau", Role: entry.RoleIssuer, Status: entry.StatusActive},
			{DID: "did:web:local.example", DisplayName: "Also local", Role: entry.RoleIssuer, Status: entry.StatusActive},
		},
		Sequence: 1, Now: t0, TTL: 24 * time.Hour, BaseURL: srv.URL, Signer: k,
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, f := range pub.Files {
		docs[path] = f.Body
	}
	docs["/jwks.json"] = ring.JWKSJSON()
	return srv, k
}

func withFederation(t *testing.T) fixture {
	t.Helper()
	f := newFixture(t, nil)
	fed, err := federation.New(federation.Options{
		Fetcher: fetchguard.New(fetchguard.Options{Guard: fetchguard.Guard{AllowPrivateNetwork: true, AllowPlainHTTP: true}}),
		Now:     func() time.Time { return *f.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.opts.Federation = fed
	return f
}

func lookupOf(t *testing.T, svc *Service, did string) *trustv1.TrustLookupResponse {
	t.Helper()
	res, err := svc.TrustLookup(context.Background(), connect.NewRequest(&trustv1.TrustLookupRequest{Identifier: didID(did), Role: commonv1.Role_ROLE_ISSUER}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}

// TestRegistryRPCsFederateAndStayReadOnly adds a registry, finds its
// entry with provenance, refuses a local edit of it, and removes it.
func TestRegistryRPCsFederateAndStayReadOnly(t *testing.T) {
	f := withFederation(t)
	ctx := context.Background()
	// A local entry that exists before the federation keeps its answer.
	upsert(t, f.svc, protoEntry("did:web:local.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_REVOKED))
	srv, key := external(t)
	added, err := f.svc.AddRegistry(ctx, connect.NewRequest(&trustv1.AddRegistryRequest{Registry: &trustv1.Registry{
		Name: "Kenya trust registry", Method: trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_LOTE_JSON, Url: srv.URL + etsi.PathJWS,
		Anchor:  &trustv1.Registry_Anchor{Anchor: &trustv1.Registry_Anchor_JwksUrl{JwksUrl: srv.URL + "/jwks.json"}},
		Refresh: durationpb.New(time.Hour),
	}}))
	if err != nil {
		t.Fatal(err)
	}
	reg := added.Msg.GetRegistry()
	if reg.GetId() == "" || reg.GetEntryCount() != 2 || reg.GetLastError() != "" || reg.GetLastSync() == nil || reg.GetSignedBy() != key.ID ||
		reg.GetRefresh().AsDuration() != time.Hour || reg.GetAnchor().GetJwksUrl() == "" {
		t.Fatalf("registry = %+v", reg)
	}
	list, err := f.svc.ListRegistries(ctx, connect.NewRequest(&trustv1.ListRegistriesRequest{}))
	if err != nil || len(list.Msg.GetRegistries()) != 1 || len(list.Msg.GetLocal()) != 2 ||
		list.Msg.GetJwksUrl() != "https://trust.example/.well-known/jwks.json" || list.Msg.GetLocal()[0].GetUrl() == "" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	got := lookupOf(t, f.svc, "did:web:registrar.go.ke")
	prov := got.GetProvenance()
	if got.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED || prov.GetRegistryId() != reg.GetId() ||
		prov.GetRegistryName() != "Kenya trust registry" || prov.GetMethod() != trustv1.Method_METHOD_ETSI ||
		prov.GetListUrl() != srv.URL+etsi.PathJWS || prov.GetKeyId() != key.ID || !prov.GetCached() {
		t.Fatalf("external lookup = %+v", got)
	}
	if local := lookupOf(t, f.svc, "did:web:local.example"); local.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED || local.GetProvenance().GetRegistryId() != "" {
		t.Fatalf("the local answer lost to the external one: %+v", local)
	}
	if _, err = f.svc.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: protoEntry("did:web:registrar.go.ke", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_REVOKED)})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a local edit of an external entry = %v", err)
	}
	if _, err = f.svc.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: didID("did:web:registrar.go.ke")})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a local delete of an external entry = %v", err)
	}
	synced, err := f.svc.SyncRegistry(ctx, connect.NewRequest(&trustv1.SyncRegistryRequest{Id: reg.GetId()}))
	if err != nil || synced.Msg.GetRegistry().GetLastError() != "" {
		t.Fatalf("sync = %+v, %v", synced, err)
	}
	if _, err := f.svc.RemoveRegistry(ctx, connect.NewRequest(&trustv1.RemoveRegistryRequest{Id: reg.GetId()})); err != nil {
		t.Fatal(err)
	}
	if gone := lookupOf(t, f.svc, "did:web:registrar.go.ke"); gone.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_UNKNOWN {
		t.Fatalf("after remove = %+v", gone)
	}
	if _, err := f.svc.RemoveRegistry(ctx, connect.NewRequest(&trustv1.RemoveRegistryRequest{Id: reg.GetId()})); code(err) != connect.CodeNotFound {
		t.Fatalf("a second remove = %v", err)
	}
	if _, err := f.svc.SyncRegistry(ctx, connect.NewRequest(&trustv1.SyncRegistryRequest{Id: "missing"})); code(err) != connect.CodeNotFound {
		t.Fatalf("sync of an unknown id = %v", err)
	}
}

func TestAddRegistryValidates(t *testing.T) {
	f := withFederation(t)
	ctx := context.Background()
	for name, r := range map[string]*trustv1.Registry{
		"empty":     nil,
		"no anchor": {Name: "N", Method: trustv1.RegistryMethod_REGISTRY_METHOD_DEDI, Url: "https://dedi.example"},
		"xml jwks": {Name: "N", Method: trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_TSL_XML, Url: "https://tsl.example/tl.xml",
			Anchor: &trustv1.Registry_Anchor{Anchor: &trustv1.Registry_Anchor_JwksUrl{JwksUrl: "https://tsl.example/jwks.json"}}},
		"no method": {Name: "N", Url: "https://x.example", Anchor: &trustv1.Registry_Anchor{Anchor: &trustv1.Registry_Anchor_X509Certificate{X509Certificate: "x"}}},
	} {
		if _, err := f.svc.AddRegistry(ctx, connect.NewRequest(&trustv1.AddRegistryRequest{Registry: r})); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A registry with an X.509 anchor and a failed read comes back with
	// its reason and the TSL method.
	res, err := f.svc.AddRegistry(ctx, connect.NewRequest(&trustv1.AddRegistryRequest{Registry: &trustv1.Registry{
		Name: "EU list", Method: trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_TSL_XML, Url: "http://127.0.0.1:1/tl.xml",
		Anchor: &trustv1.Registry_Anchor{Anchor: &trustv1.Registry_Anchor_X509Certificate{X509Certificate: testCertificate}},
	}}))
	if err != nil || res.Msg.GetRegistry().GetLastError() == "" || res.Msg.GetRegistry().GetMethod() != trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_TSL_XML ||
		res.Msg.GetRegistry().GetAnchor().GetX509Certificate() == "" || res.Msg.GetRegistry().GetLastSync() != nil {
		t.Fatalf("add = %+v, %v", res, err)
	}
	if registryMethodProto("x") != trustv1.RegistryMethod_REGISTRY_METHOD_UNSPECIFIED || lookupMethod(federation.MethodDedi) != trustv1.Method_METHOD_DEDI {
		t.Fatal("enum helpers")
	}
}

// testCertificate is the anchor of the xmldsig fixtures.
const testCertificate = `-----BEGIN CERTIFICATE-----
MIIBwzCCAWmgAwIBAgIUS7CieYh9kL0Q5RjR6nau/bnHfM4wCgYIKoZIzj0EAwIw
VzELMAkGA1UEBhMCS0UxKjAoBgNVBAoMIUNvbW11bmljYXRpb25zIEF1dGhvcml0
eSBvZiBLZW55YTEcMBoGA1UEAwwTVHJ1c3RlZCBMaXN0IEFuY2hvcjAeFw0yNjAx
MDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMFcxCzAJBgNVBAYTAktFMSowKAYDVQQK
DCFDb21tdW5pY2F0aW9ucyBBdXRob3JpdHkgb2YgS2VueWExHDAaBgNVBAMME1Ry
dXN0ZWQgTGlzdCBBbmNob3IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATItMWZ
7OkZ+KEZxXN+ZIh6IIg+vdiTTOGdVXpFYtmx29ImHzYdXG0wahG2egh9o/+lOBV5
BjfX+tSRWIobiXCsoxMwETAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA
MEUCIC73T2MGFoPRuz/5oMXXclHNPpJwjKdWAOfIW3r7Nis+AiEAwEp+JWrqkvKR
UDajNP3CHw4K3XIOMjuWSTmYMEUywt0=
-----END CERTIFICATE-----
`

// TestExportSnapshotIsSignedWithProvenance exports the local entries and
// the external copy in one snapshot that the ring of the registry
// signs. A pending entry stays out, as it stays out of the lists.
func TestExportSnapshotIsSignedWithProvenance(t *testing.T) {
	f := withFederation(t)
	ctx := context.Background()
	upsert(t, f.svc, protoEntry("did:web:education.go.ke", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE))
	upsert(t, f.svc, protoEntry("did:web:waiting.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_PENDING))
	srv, key := external(t)
	added, err := f.svc.AddRegistry(ctx, connect.NewRequest(&trustv1.AddRegistryRequest{Registry: &trustv1.Registry{
		Name: "Kenya trust registry", Method: trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_LOTE_JSON, Url: srv.URL + etsi.PathJWS,
		Anchor: &trustv1.Registry_Anchor{Anchor: &trustv1.Registry_Anchor_JwksUrl{JwksUrl: srv.URL + "/jwks.json"}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.ExportSnapshot(ctx, connect.NewRequest(&trustv1.ExportSnapshotRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	claims, kid, err := trustsnap.Verify(res.Msg.GetJws(), f.ring.JWKS(), t0)
	if err != nil || kid != f.ring.Active().ID || res.Msg.GetEntryCount() != 3 || claims.Count() != 3 || len(claims.Lists) != 2 {
		t.Fatalf("snapshot = %+v, %q, %v", claims, kid, err)
	}
	local, ext := claims.Lists[0], claims.Lists[1]
	if local.RegistryID != "" || local.SignedBy != kid || local.ListURL == "" || len(local.Entities) != 1 ||
		local.Entities[0].ID() != "did:web:education.go.ke" {
		t.Fatalf("local list = %+v", local)
	}
	if ext.RegistryID != added.Msg.GetRegistry().GetId() || ext.RegistryName != "Kenya trust registry" || ext.SignedBy != key.ID ||
		ext.ListURL != srv.URL+etsi.PathJWS || len(ext.Entities) != 2 {
		t.Fatalf("external list = %+v", ext)
	}
	if got := claims.Lookup("did:web:registrar.go.ke", "", t0); got.Outcome != trustsnap.Trusted || got.RegistryName != "Kenya trust registry" {
		t.Fatalf("lookup in the snapshot = %+v", got)
	}
}
