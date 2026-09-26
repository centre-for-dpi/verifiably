// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
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
	if serr := svc.StageOffer(ctx, id, "staging-1"); serr != nil {
		t.Fatalf("StageOffer: %v", serr)
	}
	row, found, err := writer.Find("staging-1")
	if err != nil || !found || row.ConfigID != "FarmerCredential" || row.Claims[1] != "FM-0001" || row.StatusIndex != "12" {
		t.Fatalf("row = %+v, %v, %v", row, found, err)
	}
	if _, ok := svc.Offer(ctx, id); ok {
		t.Fatal("a claimed offer is still open")
	}
	if err := svc.StageOffer(ctx, id, "staging-2"); err == nil {
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
	if err := svc.StageSubject(ctx, "FarmerCredential", `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`, "staging-9"); err != nil {
		t.Fatalf("StageSubject: %v", err)
	}
	row, found, err := writer.Find("staging-9")
	if err != nil || !found || row.Claims[0] != "Ada Lovelace" || row.StatusURI != "" {
		t.Fatalf("row = %+v, %v, %v", row, found, err)
	}
	if err := svc.StageSubject(ctx, "FarmerCredential", `{"unknown":"x"}`, "staging-10"); err == nil {
		t.Fatal("StageSubject wrote a claim the configuration does not declare")
	}
}
