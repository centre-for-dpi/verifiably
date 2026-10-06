// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// catalogueDoctype is the doctype of the mso_mdoc entry that vca setup
// writes (internal/cli/waltid_config.go). walt.id 0.18.2 signs it into
// every mDoc of the entry: the doctype comes from the credential request
// of the wallet, and the issuer API refuses a request whose doctype is
// not the one of the entry (testdata/doc/SOURCE.md, mDoc notes).
const catalogueDoctype = "vca.mdoc"

// TestRegisterMdocNamesTheDoctypeOfTheCatalogue registers an mso_mdoc
// schema. The answer names the doctype walt.id signs, so the schema
// registry publishes it and a verifier asks for it. The claims go in the
// namespace of the schema type, and the listing names the same doctype.
func TestRegisterMdocNamesTheDoctypeOfTheCatalogue(t *testing.T) {
	svc, f := newService(t, all)
	ctx := context.Background()
	resp, err := svc.RegisterCredentialConfiguration(ctx, connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "ProofOfResidence_mso_mdoc", Format: commonv1.Format_FORMAT_MSO_MDOC, Type: "ProofOfResidence",
		},
	}))
	if err != nil {
		t.Fatalf("RegisterCredentialConfiguration: %v", err)
	}
	if got := resp.Msg.GetDoctype(); got != catalogueDoctype {
		t.Fatalf("doctype = %q, want %q, the doctype walt.id signs", got, catalogueDoctype)
	}
	if _, oerr := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "ProofOfResidence_mso_mdoc", SubjectData: `{"fullName":"Jordan Example"}`},
	})); oerr != nil {
		t.Fatalf("CreateOffer: %v", oerr)
	}
	var body map[string]any
	if rerr := f.RequestJSON("/openid4vc/mdoc/issue", &body); rerr != nil {
		t.Fatalf("the mdoc issue path was not called: %v", rerr)
	}
	if body["credentialConfigurationId"] != "vca_mso_mdoc" {
		t.Fatalf("configuration = %v, want the entry of vca setup", body["credentialConfigurationId"])
	}
	data := mustAs[map[string]any](t, body["mdocData"])
	claims := mustAs[map[string]any](t, data["ProofOfResidence"])
	if claims["fullName"] != "Jordan Example" || len(data) != 1 {
		t.Fatalf("mdocData = %v, want the claims in the namespace of the schema type", data)
	}
	list, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if got := list.Msg.GetConfigurations()[0].GetType(); got != catalogueDoctype {
		t.Fatalf("the listing names the type %q, want %q", got, catalogueDoctype)
	}
}

// TestRegisterMdocNeedsADoctypeInTheCatalogue refuses an mso_mdoc entry
// without a doctype: walt.id would refuse every credential request of
// it, so the issuer learns it at publish time.
func TestRegisterMdocNeedsADoctypeInTheCatalogue(t *testing.T) {
	svc, f := newService(t, all)
	f.SetIssuerMetadata("issuer-metadata-vca-no-doctype.json")
	_, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "ProofOfResidence_mso_mdoc", Format: commonv1.Format_FORMAT_MSO_MDOC, Type: "ProofOfResidence",
		},
	}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

// TestRegisterOtherFormatsNameNoDoctype keeps the doctype empty for a
// format that has none.
func TestRegisterOtherFormatsNameNoDoctype(t *testing.T) {
	svc, _ := newService(t, all)
	resp, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: permitID, Format: commonv1.Format_FORMAT_JWT_VC_JSON, Type: "ResidencePermitCredential",
		},
	}))
	if err != nil {
		t.Fatalf("RegisterCredentialConfiguration: %v", err)
	}
	if resp.Msg.GetDoctype() != "" {
		t.Fatalf("a jwt_vc_json configuration names the doctype %q", resp.Msg.GetDoctype())
	}
}
