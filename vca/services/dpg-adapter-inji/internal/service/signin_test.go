// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// fakeSignIn keeps the sign in sources in a map, as the holder
// authorization server keeps them in its store.
type fakeSignIn struct {
	sources map[string]authz.SignInSource
	vouched []string
	looksUp bool
	fail    error
}

func newFakeSignIn() *fakeSignIn {
	return &fakeSignIn{sources: map[string]authz.SignInSource{}, vouched: []string{"sub", "email", "phone_number", "member_no"}, looksUp: true}
}

func (f *fakeSignIn) SetSignInSource(_ context.Context, src authz.SignInSource) error {
	if f.fail != nil {
		return f.fail
	}
	f.sources[src.ConfigID] = src
	return nil
}

func (f *fakeSignIn) ClearSignInSource(_ context.Context, id string) error {
	if f.fail != nil {
		return f.fail
	}
	delete(f.sources, id)
	return nil
}

func (f *fakeSignIn) SignInSourceOf(_ context.Context, id string) (authz.SignInSource, bool, error) {
	if f.fail != nil {
		return authz.SignInSource{}, false, f.fail
	}
	src, ok := f.sources[id]
	return src, ok, nil
}

func (f *fakeSignIn) VouchedClaims() []string { return f.vouched }
func (f *fakeSignIn) LooksUp() bool           { return f.looksUp }

func memberSource(claim string) *backendv1.HolderSignInSource {
	return &backendv1.HolderSignInSource{SourceId: "register", Field: "member_no", TokenClaim: claim, SchemaId: "member", SchemaVersion: 2}
}

// TestHolderSignInSourceRoundTrip proves the issuer page stores the
// source for every configuration of a schema, reads it back with the
// claims it may name, and removes it.
func TestHolderSignInSourceRoundTrip(t *testing.T) {
	svc, _ := newService(t, both)
	signIn := newFakeSignIn()
	svc.UseSignIn(signIn)
	ctx := context.Background()
	ids := []string{"MemberCard_ldp_vc", "MemberCard_vc_sd_jwt"}
	set, err := svc.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{ConfigurationIds: ids, Source: memberSource("member_no")}))
	if err != nil || set.Msg.GetSource().GetField() != "member_no" {
		t.Fatalf("set = %v %v", set, err)
	}
	for _, id := range ids {
		if got := signIn.sources[id]; got.SourceID != "register" || got.TokenClaim != "member_no" || got.SchemaID != "member" || got.SchemaVersion != 2 || got.ConfigID != id {
			t.Fatalf("stored for %s = %+v", id, got)
		}
	}
	got, err := svc.GetHolderSignInSource(ctx, connect.NewRequest(&backendv1.GetHolderSignInSourceRequest{ConfigurationIds: append([]string{"Other"}, ids...)}))
	if err != nil || got.Msg.GetSource().GetSourceId() != "register" || !slices.Equal(got.Msg.GetVouchedClaims(), signIn.vouched) {
		t.Fatalf("get = %v %v", got, err)
	}
	if _, cerr := svc.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{ConfigurationIds: ids, Clear: true})); cerr != nil {
		t.Fatal(cerr)
	}
	if len(signIn.sources) != 0 {
		t.Fatalf("clear left %v", signIn.sources)
	}
	got, err = svc.GetHolderSignInSource(ctx, connect.NewRequest(&backendv1.GetHolderSignInSourceRequest{ConfigurationIds: ids}))
	if err != nil || got.Msg.GetSource() != nil || len(got.Msg.GetVouchedClaims()) == 0 {
		t.Fatalf("get after clear = %v %v", got, err)
	}
}

// TestHolderSignInSourceNeedsAVouchedClaim proves the source names only
// a claim the holder provider vouches for (ADR-056 decision 2), and
// every part of it.
func TestHolderSignInSourceNeedsAVouchedClaim(t *testing.T) {
	svc, _ := newService(t, both)
	svc.UseSignIn(newFakeSignIn())
	ctx := context.Background()
	for name, req := range map[string]*backendv1.SetHolderSignInSourceRequest{
		"a claim the holder picks": {ConfigurationIds: []string{"c"}, Source: memberSource("preferred_username")},
		"no configuration":         {Source: memberSource("sub")},
		"an empty configuration":   {ConfigurationIds: []string{" "}, Source: memberSource("sub")},
		"no source":                {ConfigurationIds: []string{"c"}},
		"no field":                 {ConfigurationIds: []string{"c"}, Source: &backendv1.HolderSignInSource{SourceId: "s", TokenClaim: "sub", SchemaId: "m"}},
		"no schema":                {ConfigurationIds: []string{"c"}, Source: &backendv1.HolderSignInSource{SourceId: "s", Field: "f", TokenClaim: "sub"}},
	} {
		_, err := svc.SetHolderSignInSource(ctx, connect.NewRequest(req))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
}

// TestHolderSignInSourceNeedsTheServer proves an adapter without the
// holder authorization server refuses both calls, and a store failure
// is an internal error.
func TestHolderSignInSourceNeedsTheServer(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	_, err := svc.GetHolderSignInSource(ctx, connect.NewRequest(&backendv1.GetHolderSignInSourceRequest{ConfigurationIds: []string{"c"}}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	_, err = svc.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{ConfigurationIds: []string{"c"}, Source: memberSource("sub")}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	signIn := newFakeSignIn()
	signIn.looksUp = false
	svc.UseSignIn(signIn)
	_, err = svc.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{ConfigurationIds: []string{"c"}, Source: memberSource("sub")}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	signIn.looksUp, signIn.fail = true, errors.New("disk full")
	_, err = svc.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{ConfigurationIds: []string{"c"}, Source: memberSource("sub")}))
	wantCode(t, err, connect.CodeInternal)
	_, err = svc.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{ConfigurationIds: []string{"c"}, Clear: true}))
	wantCode(t, err, connect.CodeInternal)
	_, err = svc.GetHolderSignInSource(ctx, connect.NewRequest(&backendv1.GetHolderSignInSourceRequest{ConfigurationIds: []string{"c"}}))
	wantCode(t, err, connect.CodeInternal)
}

// TestHolderSignInFeatureListed lists the feature only for an issuer
// whose holder authorization server can ask a data source.
func TestHolderSignInFeatureListed(t *testing.T) {
	has := func(svc *service.Service) bool {
		caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_HOLDER_SIGN_IN_SOURCE)
	}
	on, _ := newService(t, both)
	on.UseSignIn(newFakeSignIn())
	off, _ := newService(t, both)
	blind, _ := newService(t, both)
	noLookup := newFakeSignIn()
	noLookup.looksUp = false
	blind.UseSignIn(noLookup)
	if !has(on) || has(off) || has(blind) {
		t.Fatalf("listed: on %v, off %v, no lookup %v", has(on), has(off), has(blind))
	}
}

// TestGetPresentationRequirementReadsBack proves the settings card sees
// what the issuer stored, and nothing after a clear.
func TestGetPresentationRequirementReadsBack(t *testing.T) {
	svc, _ := newServiceWith(t, both, withPresentation)
	ctx := context.Background()
	empty, err := svc.GetPresentationRequirement(ctx, connect.NewRequest(&backendv1.GetPresentationRequirementRequest{}))
	if err != nil || empty.Msg.GetRequirement() != nil || !slices.Equal(empty.Msg.GetIdentityClaims(), []string{"vcaSubject", "nationalId"}) {
		t.Fatalf("before a set = %v %v", empty, err)
	}
	set := setRequirement(t, svc)
	got, err := svc.GetPresentationRequirement(ctx, connect.NewRequest(&backendv1.GetPresentationRequirementRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	req := got.Msg.GetRequirement()
	if req.GetCredentialType() != "NationalIdentityCredential" || req.GetFormat() != commonv1.Format_FORMAT_LDP_VC ||
		!slices.Equal(req.GetRequiredClaims(), []string{"vcaSubject"}) || req.GetPurpose() == "" || got.Msg.GetDefinitionJson() != set.GetDefinitionJson() {
		t.Fatalf("read back = %v", got.Msg)
	}
	if _, cerr := svc.SetPresentationRequirement(ctx, connect.NewRequest(&backendv1.SetPresentationRequirementRequest{Clear: true})); cerr != nil {
		t.Fatal(cerr)
	}
	got, err = svc.GetPresentationRequirement(ctx, connect.NewRequest(&backendv1.GetPresentationRequirementRequest{}))
	if err != nil || got.Msg.GetRequirement() != nil || got.Msg.GetDefinitionJson() != "" {
		t.Fatalf("after a clear = %v %v", got, err)
	}
	off, _ := newService(t, both)
	_, err = off.GetPresentationRequirement(ctx, connect.NewRequest(&backendv1.GetPresentationRequirementRequest{}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}
