// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"slices"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// identitySchema carries claims that the QR specification 1.1.0 names.
const identitySchema = `{"type":"object","properties":{"fullName":{"type":"string"},` +
	`"dateOfBirth":{"type":"string"},"gender":{"type":"string"},"mobileNumber":{"type":"string"}}}`

// TestChannelListed lists the identity QR channel with an Inji Certify
// URL, and not on a verifier only deployment.
func TestChannelListed(t *testing.T) {
	svc, _ := newService(t, both)
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(caps.Msg.GetChannels(), backendv1.Channel_CHANNEL_CLAIM169_QR) {
		t.Fatalf("channels = %v", caps.Msg.GetChannels())
	}
	verifier, _ := newService(t, roles{verify: true})
	caps, err = verifier.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(caps.Msg.GetChannels(), backendv1.Channel_CHANNEL_CLAIM169_QR) {
		t.Fatal("a verifier only deployment lists the identity QR channel")
	}
}

// TestIssueReturnsTheIdentityQR registers a configuration with identity
// claims, so Certify signs a Claim 169 code beside the credential. Issue
// returns the code, and the ingest decoder of the scanner reads it. A
// configuration without such claims gives no code.
func TestIssueReturnsTheIdentityQR(t *testing.T) {
	svc, _ := newService(t, both)
	if _, err := register(svc, &backendv1.CredentialConfiguration{
		Id: "NationalId_ldp_vc", Format: commonv1.Format_FORMAT_LDP_VC, Type: "NationalIdentityCredential",
		JsonSchema: identitySchema,
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{Spec: &backendv1.IssueSpec{
		ConfigurationId: "NationalId_ldp_vc",
		SubjectData:     `{"fullName":"Wanjiku Njeri","dateOfBirth":"1987-04-12","gender":"Female","mobileNumber":"+254712345678"}`,
	}}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cwt, steps, err := ingest.DecodeClaim169(resp.Msg.GetClaim169Qr())
	if err != nil {
		t.Fatalf("the identity QR must decode: %v (%v)", err, steps)
	}
	if cwt.Data["4"] != "Wanjiku Njeri" {
		t.Fatalf("claim 169 = %v", cwt.Data)
	}

	plain, err := svc.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{Spec: farmerSpec()}))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Msg.GetClaim169Qr() != "" {
		t.Fatalf("a configuration without qrSettings gives a code: %q", plain.Msg.GetClaim169Qr())
	}
}
