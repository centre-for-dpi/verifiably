// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/trustsnap"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/cache"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/sets"
)

const trustURL = "http://trust-registry:8085"

// cached builds the fixture service with a trust cache. The trust
// registry answers the sync and then goes down, so the trust check
// reads the copy. It returns the clock.
func cached(t *testing.T) (fixture, *time.Time) {
	t.Helper()
	f := newFixture(t)
	now := testNow
	clock := func() time.Time { return now }
	regKey, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(regKey, "registry-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JWKS{Keys: []jose.JWK{pub}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := jose.Sign(regKey, "registry-key", trustsnap.Type, trustsnap.Claims{
		ExpiresAt: testNow.Add(time.Hour).Unix(),
		Lists: []trustsnap.List{{RegistryName: "Kenya trust registry", Entities: []trustsnap.Entity{{
			Name: "Ministry", Role: trustsnap.RoleIssuer, Status: trustsnap.StatusActive,
			Identities: []trustsnap.Identity{{DID: "did:web:issuer"}},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if url == trustURL+cache.JWKSPath {
			return jwks, nil
		}
		return nil, errors.New("404")
	}
	c, err := cache.New(cache.Options{
		KV: store.Memory(), TrustURL: trustURL, Fetch: fetch, Now: clock,
		Snapshot: func(context.Context) (string, error) { return snapshot, nil },
		Defaults: cache.Policy{AllowOffline: true, MarkStale: true},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.opts.Cache = c
	f.svc.opts.Now = clock
	f.svc.opts.Ports.Trust = c.Trust(func(context.Context, string, string) (policy.Trust, error) {
		return policy.Trust{}, errors.New("the trust registry is down")
	})
	return f, &now
}

// TestResultCarriesCacheAge evaluates with the trust registry down. The
// answer comes from the copy, and the response names its age.
func TestResultCarriesCacheAge(t *testing.T) {
	f, now := cached(t)
	ctx := context.Background()
	if _, err := f.svc.SyncCache(ctx, connect.NewRequest(&policyv1.SyncCacheRequest{})); err != nil {
		t.Fatal(err)
	}
	*now = testNow.Add(7 * time.Hour)
	resp, err := f.svc.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: f.presentation(t, "verifier", "n1"), Nonce: "n1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	msg := resp.Msg
	if msg.GetVerdict() != policyv1.EvaluateResponse_VERDICT_VALID {
		t.Fatalf("verdict = %s: %+v", msg.GetVerdict(), msg.GetChecks())
	}
	if msg.GetMaterialAge().AsDuration() != 7*time.Hour || !msg.GetMaterialStale() {
		t.Fatalf("material age = %v, stale %v", msg.GetMaterialAge(), msg.GetMaterialStale())
	}
	for _, c := range msg.GetChecks() {
		if c.GetName() == policy.NameTrustChain && c.GetCredentialIndex() == 0 && c.GetEvidence()["registry"] != "Kenya trust registry" {
			t.Fatalf("trust evidence = %v", c.GetEvidence())
		}
	}
	// An evaluation that read no copy carries no age.
	plain := newFixture(t)
	online, err := plain.svc.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: plain.presentation(t, "verifier", "n1"), Nonce: "n1",
	}))
	if err != nil || online.Msg.GetMaterialAge() != nil || online.Msg.GetMaterialStale() {
		t.Fatalf("an online evaluation = %+v, %v", online.Msg, err)
	}
}

// TestCacheRPCs reads the state, syncs one kind, and stores a policy.
func TestCacheRPCs(t *testing.T) {
	f, _ := cached(t)
	ctx := context.Background()
	synced, err := f.svc.SyncCache(ctx, connect.NewRequest(&policyv1.SyncCacheRequest{Kind: policyv1.CacheKind_CACHE_KIND_TRUST_LIST}))
	if err != nil || synced.Msg.GetFailed() != 0 || len(synced.Msg.GetKinds()) != 3 {
		t.Fatalf("SyncCache = %+v, %v", synced, err)
	}
	trust := synced.Msg.GetKinds()[0]
	if trust.GetKind() != policyv1.CacheKind_CACHE_KIND_TRUST_LIST || trust.GetSources() != 1 || trust.GetItems() != 1 ||
		trust.GetIssuers() != 1 || trust.GetSyncedAt() == nil || trust.GetNextSync() == nil {
		t.Fatalf("trust state = %+v", trust)
	}
	src := synced.Msg.GetSources()[0]
	if src.GetSource() != trustURL || src.GetSignedBy() != "registry-key" || src.GetItemCount() != 1 || src.GetSyncedAt() == nil || src.GetReadAt() == nil {
		t.Fatalf("trust source = %+v", src)
	}
	state, err := f.svc.GetCacheState(ctx, connect.NewRequest(&policyv1.GetCacheStateRequest{}))
	if err != nil || !state.Msg.GetPolicy().GetAllowOffline() || state.Msg.GetPolicy().GetTrustListRefresh().AsDuration() != 6*time.Hour {
		t.Fatalf("GetCacheState = %+v, %v", state, err)
	}
	set, err := f.svc.SetCachePolicy(ctx, connect.NewRequest(&policyv1.SetCachePolicyRequest{Policy: &policyv1.CachePolicy{
		TrustListRefresh: durationpb.New(2 * time.Hour), OfflineWindow: durationpb.New(72 * time.Hour),
		AllowOffline: true, RefuseStaleStatus: true,
	}}))
	p := set.Msg.GetPolicy()
	if err != nil || p.GetTrustListRefresh().AsDuration() != 2*time.Hour || p.GetKeysRefresh().AsDuration() != 24*time.Hour ||
		p.GetOfflineWindow().AsDuration() != 72*time.Hour || p.GetMarkStale() || !p.GetRefuseStaleStatus() {
		t.Fatalf("SetCachePolicy = %+v, %v", p, err)
	}
	if _, err := f.svc.SetCachePolicy(ctx, connect.NewRequest(&policyv1.SetCachePolicyRequest{Policy: &policyv1.CachePolicy{
		OfflineWindow: durationpb.New(8 * 24 * time.Hour),
	}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a window of 8 days = %v", err)
	}
	if kindOf(policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS) != cache.KindKeys || kindOf(policyv1.CacheKind_CACHE_KIND_STATUS_LIST) != cache.KindStatus ||
		kindProto("other") != policyv1.CacheKind_CACHE_KIND_UNSPECIFIED {
		t.Fatal("kind helpers")
	}
}

// TestCacheRPCsWithoutCache answer FailedPrecondition.
func TestCacheRPCsWithoutCache(t *testing.T) {
	s, err := New(Options{Sets: sets.New(store.Memory(), nil)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, e1 := s.GetCacheState(ctx, connect.NewRequest(&policyv1.GetCacheStateRequest{}))
	_, e2 := s.SyncCache(ctx, connect.NewRequest(&policyv1.SyncCacheRequest{}))
	_, e3 := s.SetCachePolicy(ctx, connect.NewRequest(&policyv1.SetCachePolicyRequest{}))
	for _, err := range []error{e1, e2, e3} {
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("want FailedPrecondition, got %v", err)
		}
	}
}
