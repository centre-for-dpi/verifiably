// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

const authzIssuer = "https://adapter.example/authz"

// newHolderService is the service with the holder authorization server
// on, and the claims store it writes.
func newHolderService(t *testing.T) (*service.Service, *claims.Writer) {
	t.Helper()
	var writer *claims.Writer
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) {
		o.AuthzIssuer = authzIssuer + "/"
		o.OfferIssuer = "http://inji-certify-nginx:8091"
		writer = o.Claims
	})
	return svc, writer
}

// boundSpec is an offer bound to the member number of the subject.
func boundSpec() *backendv1.IssueSpec {
	spec := farmerSpec()
	spec.BindingRule = &backendv1.BindingRule{TokenClaim: "preferred_username", SubjectClaim: "farmerID"}
	return spec
}

// TestAuthorizationCodeOfferNamesTheAdapter: with the holder
// authorization server on, the offer names it as the authorization
// server, its issuer_state is the offer id, and no row exists before a
// holder signs in (ADR-052 decision 3).
func TestAuthorizationCodeOfferNamesTheAdapter(t *testing.T) {
	svc, writer := newHolderService(t)
	ctx := context.Background()
	resp, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: boundSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	id := resp.Msg.GetOfferId()
	document, ok := svc.HostedOffer(ctx, id)
	if !ok {
		t.Fatal("the offer document is missing")
	}
	var offer map[string]any
	if uerr := json.Unmarshal([]byte(document), &offer); uerr != nil {
		t.Fatal(uerr)
	}
	grant := mustAs[map[string]any](t, mustAs[map[string]any](t, offer["grants"])["authorization_code"])
	if grant["authorization_server"] != authzIssuer || grant["issuer_state"] != id {
		t.Fatalf("grant = %v, want the adapter and the offer id", grant)
	}
	if offer["credential_issuer"] != "http://inji-certify-nginx:8091" {
		t.Fatalf("credential_issuer = %v", offer["credential_issuer"])
	}
	entries, err := writer.Sweep()
	if err != nil || entries != 0 {
		t.Fatalf("Sweep = %d, %v", entries, err)
	}
	open, ok := svc.Offer(ctx, id)
	if !ok || open.ConfigID != "FarmerCredential" || open.Subject["farmerID"] != "FM-0001" ||
		open.Binding != (authz.Binding{TokenClaim: "preferred_username", SubjectClaim: "farmerID"}) {
		t.Fatalf("Offer = %+v, %v", open, ok)
	}
	// The claim writes the row under the key of the token, once.
	if serr := svc.StageOffer(ctx, id, "staging-1", fixedTime.Add(authz.RowTTL)); serr != nil {
		t.Fatalf("StageOffer: %v", serr)
	}
	row, found, err := writer.Find("staging-1")
	if err != nil || !found || row.ConfigID != "FarmerCredential" || row.Claims[1] != "FM-0001" || row.StatusIndex != "12" {
		t.Fatalf("row = %+v, %v, %v", row, found, err)
	}
	if _, ok := svc.Offer(ctx, id); ok {
		t.Fatal("a claimed offer is still open")
	}
	if err := svc.StageOffer(ctx, id, "staging-2", fixedTime.Add(authz.RowTTL)); err == nil {
		t.Fatal("a second claim of the offer worked")
	}
	if err := svc.Unstage(ctx, "staging-1"); err != nil {
		t.Fatal(err)
	}
	if _, found, ferr := writer.Find("staging-1"); ferr != nil || found {
		t.Fatalf("Unstage left the row: %v", ferr)
	}
	if _, ok := svc.Offer(ctx, "no-such-offer"); ok {
		t.Fatal("an unknown offer is open")
	}
}

// TestHolderOfferChecksTheBindingRule: the default rule needs an email
// of the subject, and a rule must name both claims.
func TestHolderOfferChecksTheBindingRule(t *testing.T) {
	svc, _ := newHolderService(t)
	ctx := context.Background()
	for name, spec := range map[string]*backendv1.IssueSpec{
		"no email for the default rule": farmerSpec(),
		"half a rule": func() *backendv1.IssueSpec {
			s := farmerSpec()
			s.BindingRule = &backendv1.BindingRule{TokenClaim: "email"}
			return s
		}(),
		"a subject claim that is not text": func() *backendv1.IssueSpec {
			s := farmerSpec()
			s.SubjectData = `{"fullName":"Ada Lovelace","farmerID":7,"district":"Nakuru"}`
			s.BindingRule = &backendv1.BindingRule{TokenClaim: "sub", SubjectClaim: "farmerID"}
			return s
		}(),
		"an unknown claim": func() *backendv1.IssueSpec {
			s := boundSpec()
			s.SubjectData = `{"fullName":"Ada Lovelace","farmerID":"FM-1","other":"x"}`
			return s
		}(),
	} {
		_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
			Spec: spec, Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
		}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: CreateOffer = %v", name, err)
		}
	}
	// A subject with an email takes the default rule.
	spec := farmerSpec()
	spec.ConfigurationId = "IdentityCredential"
	spec.SubjectData = `{"given_name":"Ada","family_name":"Lovelace","birth_date":"1990-01-02"}`
	_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: spec, Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a subject without an email took the default rule: %v", err)
	}
}

// TestStageSubjectWritesTheRowOfASignIn: a claim without an offer writes
// the row that the sign in source returned.
func TestStageSubjectWritesTheRowOfASignIn(t *testing.T) {
	svc, writer := newHolderService(t)
	ctx := context.Background()
	if err := svc.StageSubject(ctx, "FarmerCredential", `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`, "staging-9", fixedTime.Add(authz.RowTTL)); err != nil {
		t.Fatalf("StageSubject: %v", err)
	}
	row, found, err := writer.Find("staging-9")
	if err != nil || !found || row.Claims[0] != "Ada Lovelace" || row.StatusURI != "" {
		t.Fatalf("row = %+v, %v, %v", row, found, err)
	}
	if err := svc.StageSubject(ctx, "FarmerCredential", `{"unknown":"x"}`, "staging-10", fixedTime.Add(authz.RowTTL)); err == nil {
		t.Fatal("StageSubject wrote a claim the configuration does not declare")
	}
}

// TestAClaimedOfferKeepsNoSubject is finding 5 of the review: an offer
// of the authorization code channel kept the whole subject in the store
// of the adapter for ever. The row of the claim lives as long as the
// server says, and once the holder has the token the offer keeps only
// its document (ADR-056 decisions 3 and 4).
func TestAClaimedOfferKeepsNoSubject(t *testing.T) {
	var kv store.KeyValue
	var writer *claims.Writer
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) {
		o.AuthzIssuer = authzIssuer
		kv, writer = o.Store, o.Claims
	})
	ctx := context.Background()
	resp, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: boundSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	id := resp.Msg.GetOfferId()
	ends := fixedTime.Add(authz.RowTTL)
	if serr := svc.StageOffer(ctx, id, "staging-1", ends); serr != nil {
		t.Fatalf("StageOffer: %v", serr)
	}
	row, found, err := writer.Find("staging-1")
	if err != nil || !found || !row.ExpiresAt.Equal(ends) {
		t.Fatalf("row = %+v, %v, %v; want the end %v", row, found, err, ends)
	}
	if ferr := svc.Finish(ctx, id); ferr != nil {
		t.Fatalf("Finish: %v", ferr)
	}
	raw, err := kv.Get(ctx, "offer/"+id)
	if err != nil {
		t.Fatal(err)
	}
	for _, personal := range []string{"Ada Lovelace", "FM-0001", "Nakuru", "spec", "binding"} {
		if strings.Contains(string(raw), personal) {
			t.Errorf("the finished offer still holds %q: %s", personal, raw)
		}
	}
	if _, ok := svc.HostedOffer(ctx, id); !ok {
		t.Error("the offer document went before the offer expired")
	}
	if _, ok := svc.Offer(ctx, id); ok {
		t.Error("a finished offer is open")
	}
	if serr := svc.StageOffer(ctx, id, "staging-2", ends); serr == nil {
		t.Error("a finished offer was claimed again")
	}
	// A second finish, or the finish of an offer the sweep removed,
	// changes nothing.
	for _, again := range []string{id, "gone"} {
		if ferr := svc.Finish(ctx, again); ferr != nil {
			t.Errorf("Finish(%s) = %v", again, ferr)
		}
	}
}

// TestTheSweepDeletesExpiredOffers: the sweep removes every offer
// document after its end, claimed or not, with the subject it held
// (ADR-056 decision 4).
func TestTheSweepDeletesExpiredOffers(t *testing.T) {
	now := fixedTime
	var kv store.KeyValue
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) {
		o.AuthzIssuer = authzIssuer
		o.Now = func() time.Time { return now }
		kv = o.Store
	})
	ctx := context.Background()
	offer := func() string {
		t.Helper()
		resp, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
			Spec: boundSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
		}))
		if err != nil {
			t.Fatalf("CreateOffer: %v", err)
		}
		return resp.Msg.GetOfferId()
	}
	old := offer()
	now = now.Add(15*time.Minute + time.Second)
	fresh := offer()
	if err := kv.Put(ctx, "offer/broken", []byte("{")); err != nil {
		t.Fatal(err)
	}
	removed, err := svc.SweepOffers(ctx)
	if err != nil || removed != 2 {
		t.Fatalf("SweepOffers = %d, %v; want 2", removed, err)
	}
	for id, want := range map[string]bool{old: false, fresh: true, "broken": false} {
		_, err := kv.Get(ctx, "offer/"+id)
		if (err == nil) != want {
			t.Errorf("offer %s kept = %v, want %v", id, err == nil, want)
		}
	}
}

// TestAFailedCodeReopensTheOffer: the authorization server reopens an
// offer whose code failed before any token, so the holder claims it
// again. An offer that gave its token, or that is gone, stays shut
// (ADR-056 decision 4).
func TestAFailedCodeReopensTheOffer(t *testing.T) {
	svc, _ := newHolderService(t)
	ctx := context.Background()
	resp, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: boundSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	id := resp.Msg.GetOfferId()
	if serr := svc.StageOffer(ctx, id, "staging-1", fixedTime.Add(authz.RowTTL)); serr != nil {
		t.Fatal(serr)
	}
	if rerr := svc.Reopen(ctx, id); rerr != nil {
		t.Fatalf("Reopen: %v", rerr)
	}
	if _, ok := svc.Offer(ctx, id); !ok {
		t.Fatal("the reopened offer is shut")
	}
	if serr := svc.StageOffer(ctx, id, "staging-2", fixedTime.Add(authz.RowTTL)); serr != nil {
		t.Fatalf("the second claim: %v", serr)
	}
	if ferr := svc.Finish(ctx, id); ferr != nil {
		t.Fatal(ferr)
	}
	for _, shut := range []string{id, "gone"} {
		if rerr := svc.Reopen(ctx, shut); rerr == nil {
			t.Errorf("Reopen(%s) worked", shut)
		}
	}
}

// TestCreateOfferRefusesAControlCharacter: a claim value with a NUL or
// another control character fails at CreateOffer, before any row
// reaches the claims store (ADR-056 decision 7).
func TestCreateOfferRefusesAControlCharacter(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	for _, value := range []string{`Ada\u0000`, `Ada\u001b[1m`, `Ada\u007f`} {
		spec := farmerSpec()
		spec.SubjectData = `{"fullName":"` + value + `","farmerID":"FM-0001","district":"Nakuru"}`
		_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{Spec: spec}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "fullName") {
			t.Errorf("%s: CreateOffer = %v", value, err)
		}
	}
	spec := farmerSpec()
	spec.SubjectData = `{"fullName":"Ada\tLovelace","farmerID":"FM-0001","district":"Nakuru"}`
	if _, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{Spec: spec})); err != nil {
		t.Errorf("a tab: CreateOffer = %v", err)
	}
}
