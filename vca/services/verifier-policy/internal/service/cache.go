// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/cache"
)

// errNoCache reports a deployment without a trust cache.
var errNoCache = errors.New("service: this deployment keeps no trust cache")

// GetCacheState returns the cache policy and the state of each source
// (ADR-041 decision 5).
func (s *Service) GetCacheState(ctx context.Context, _ *connect.Request[policyv1.GetCacheStateRequest]) (
	*connect.Response[policyv1.GetCacheStateResponse], error) {
	if s.opts.Cache == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errNoCache)
	}
	state, err := s.opts.Cache.State(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	kinds, sources := stateProto(state)
	return connect.NewResponse(&policyv1.GetCacheStateResponse{
		Policy: cachePolicyProto(state.Policy), Kinds: kinds, Sources: sources,
	}), nil
}

// SyncCache reads one kind now, or every kind (ADR-041 decision 1).
func (s *Service) SyncCache(ctx context.Context, req *connect.Request[policyv1.SyncCacheRequest]) (
	*connect.Response[policyv1.SyncCacheResponse], error) {
	if s.opts.Cache == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errNoCache)
	}
	failed, err := s.opts.Cache.Sync(ctx, kindOf(req.Msg.GetKind()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	state, err := s.opts.Cache.State(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	kinds, sources := stateProto(state)
	return connect.NewResponse(&policyv1.SyncCacheResponse{Kinds: kinds, Sources: sources, Failed: count(failed)}), nil
}

// SetCachePolicy stores the refresh intervals and the offline window
// (ADR-041 decisions 2, 3, and 4).
func (s *Service) SetCachePolicy(ctx context.Context, req *connect.Request[policyv1.SetCachePolicyRequest]) (
	*connect.Response[policyv1.SetCachePolicyResponse], error) {
	if s.opts.Cache == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errNoCache)
	}
	stored, err := s.opts.Cache.SetPolicy(ctx, cachePolicyOf(req.Msg.GetPolicy()))
	switch {
	case errors.Is(err, cache.ErrPolicy):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&policyv1.SetCachePolicyResponse{Policy: cachePolicyProto(stored)}), nil
}

// kindOf maps a proto kind to a cache kind. Unspecified gives every kind.
func kindOf(k policyv1.CacheKind) cache.Kind {
	switch k {
	case policyv1.CacheKind_CACHE_KIND_TRUST_LIST:
		return cache.KindTrust
	case policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS:
		return cache.KindKeys
	case policyv1.CacheKind_CACHE_KIND_STATUS_LIST:
		return cache.KindStatus
	case policyv1.CacheKind_CACHE_KIND_UNSPECIFIED:
	}
	return ""
}

// kindProto maps a cache kind to a proto kind.
func kindProto(k cache.Kind) policyv1.CacheKind {
	switch k {
	case cache.KindTrust:
		return policyv1.CacheKind_CACHE_KIND_TRUST_LIST
	case cache.KindKeys:
		return policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS
	case cache.KindStatus:
		return policyv1.CacheKind_CACHE_KIND_STATUS_LIST
	}
	return policyv1.CacheKind_CACHE_KIND_UNSPECIFIED
}

// cachePolicyOf maps a proto policy. An empty duration stays zero, so
// the cache fills its default.
func cachePolicyOf(p *policyv1.CachePolicy) cache.Policy {
	return cache.Policy{
		TrustRefresh: duration(p.GetTrustListRefresh()), KeysRefresh: duration(p.GetKeysRefresh()),
		StatusRefresh: duration(p.GetStatusListRefresh()), AllowOffline: p.GetAllowOffline(),
		Window: duration(p.GetOfflineWindow()), MarkStale: p.GetMarkStale(), RefuseStaleStatus: p.GetRefuseStaleStatus(),
	}
}

// duration returns a proto duration, or zero when it is empty.
func duration(d *durationpb.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return d.AsDuration()
}

// cachePolicyProto maps a cache policy.
func cachePolicyProto(p cache.Policy) *policyv1.CachePolicy {
	return &policyv1.CachePolicy{
		TrustListRefresh: durationpb.New(p.TrustRefresh), KeysRefresh: durationpb.New(p.KeysRefresh),
		StatusListRefresh: durationpb.New(p.StatusRefresh), AllowOffline: p.AllowOffline,
		OfflineWindow: durationpb.New(p.Window), MarkStale: p.MarkStale, RefuseStaleStatus: p.RefuseStaleStatus,
	}
}

// stateProto maps the state of the cache.
func stateProto(state cache.State) ([]*policyv1.CacheKindState, []*policyv1.CacheSource) {
	kinds := make([]*policyv1.CacheKindState, 0, len(state.Kinds))
	for _, k := range state.Kinds {
		kinds = append(kinds, &policyv1.CacheKindState{
			Kind: kindProto(k.Kind), SyncedAt: stampOf(k.SyncedAt), NextSync: stampOf(k.NextSync),
			Sources: count(k.Sources), Items: count(k.Items), Issuers: count(k.Issuers), Failed: count(k.Failed),
		})
	}
	sources := make([]*policyv1.CacheSource, 0, len(state.Sources))
	for _, s := range state.Sources {
		sources = append(sources, &policyv1.CacheSource{
			Kind: kindProto(s.Kind), Source: s.Key, SyncedAt: stampOf(s.SyncedAt), ReadAt: stampOf(s.ReadAt),
			LastError: s.LastError, SignedBy: s.SignedBy, ItemCount: count(s.Items),
			RegistryId: s.RegistryID, RegistryName: s.RegistryName,
		})
	}
	return kinds, sources
}

// stampOf returns a proto time, or nil for the zero time.
func stampOf(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// count caps a count that goes into an int32 field.
func count(n int) int32 {
	return int32(min(n, 1<<31-1)) // #nosec G115 -- min caps the value
}
