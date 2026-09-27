// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// vcaEntry is a bitstring status entry of VCA that a spec names.
func vcaEntry() *backendv1.StatusListBinding {
	return &backendv1.StatusListBinding{
		Kind: backendv1.StatusListBinding_KIND_BITSTRING, ListId: "list-1", Index: 7,
		PublishUrl: "https://status.example.org/bitstring/1",
	}
}

// TestCreateOfferNamesTheStatusEntryTheCredentialCarries: walt.id
// embeds the entry of the spec in an SD-JWT or a VCDM body, so the
// answer names it. An mdoc and a body of the caller carry no entry, so
// the answer names none.
func TestCreateOfferNamesTheStatusEntryTheCredentialCarries(t *testing.T) {
	svc, _ := newService(t, all)
	registerPermit(t, svc)
	register(t, svc, &backendv1.CredentialConfiguration{
		Id: "licence-mdoc", Format: commonv1.Format_FORMAT_MSO_MDOC, Type: "org.iso.18013.5.1.mDL",
	})
	for name, c := range map[string]struct {
		spec *backendv1.IssueSpec
		want *backendv1.StatusListBinding
	}{
		"vcdm":        {&backendv1.IssueSpec{ConfigurationId: permitID, SubjectData: `{"degree":"Mathematics"}`, Status: vcaEntry()}, vcaEntry()},
		"no entry":    {&backendv1.IssueSpec{ConfigurationId: permitID, SubjectData: `{"degree":"Mathematics"}`}, nil},
		"caller body": {&backendv1.IssueSpec{ConfigurationId: permitID, CredentialData: `{"type":["VerifiableCredential"]}`, Status: vcaEntry()}, nil},
		"mdoc":        {&backendv1.IssueSpec{ConfigurationId: "licence-mdoc", SubjectData: `{"family_name":"Lovelace"}`, Status: vcaEntry()}, nil},
	} {
		resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{Spec: c.spec}))
		if err != nil {
			t.Fatalf("%s: CreateOffer: %v", name, err)
		}
		if !proto.Equal(resp.Msg.GetStatus(), c.want) {
			t.Errorf("%s: status = %v, want %v", name, resp.Msg.GetStatus(), c.want)
		}
		if resp.Msg.GetStatus().GetDpgList() || resp.Msg.GetCredentialId() != "" {
			t.Errorf("%s: walt.id keeps no status list, got %v", name, resp.Msg)
		}
	}
}
