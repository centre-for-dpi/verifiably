package waltid

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

func TestProfileIDForDocType(t *testing.T) {
	tests := []struct {
		docType       string
		wantProfileID string
		wantNamespace string
		wantOK        bool
	}{
		{"org.iso.18013.5.1.mDL", "isoMdl", "org.iso.18013.5.1", true},
		{"org.iso.23220.photoID.1", "isoPhotoId", "org.iso.23220.1", true},
		{"org.iso.7367.1.mVRC", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		got, ok := profileIDForDocType(tt.docType)
		if got.profileID != tt.wantProfileID || got.baseNamespace != tt.wantNamespace || ok != tt.wantOK {
			t.Errorf("profileIDForDocType(%q) = (%+v, %v), want (profileID=%q, namespace=%q, %v)",
				tt.docType, got, ok, tt.wantProfileID, tt.wantNamespace, tt.wantOK)
		}
	}
}

// A field the caller omits must NOT appear in the request at all. issuer-api2
// merges runtimeOverrides recursively over the profile, so any key we send
// wins but any key we omit keeps the profile's value. The versioned profile
// has its sample data emptied precisely so an omission surfaces as blank —
// but if we were to send a key with a zero value we would be asserting that
// blank on purpose, and if we send nothing the profile decides. This test
// pins the boundary: only what the operator actually filled in gets sent.
func TestBuildIssuer2OfferOmitsUnsetFields(t *testing.T) {
	schema := vctypes.Schema{
		ID:   "org.iso.18013.5.1.mDL",
		Std:  "mso_mdoc",
		Name: "Driver's Licence",
	}
	subject := map[string]string{
		"family_name": "Perez",
		"given_name":  "Ana",
	}

	req, err := buildIssuer2Offer(schema, subject)
	if err != nil {
		t.Fatalf("buildIssuer2Offer: %v", err)
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "Perez") || !strings.Contains(body, "Ana") {
		t.Errorf("supplied fields missing from request: %s", body)
	}
	for _, absent := range []string{"nationality", "issuing_country", "birth_date"} {
		if strings.Contains(body, absent) {
			t.Errorf("unsupplied field %q leaked into request — it would inherit the profile's sample value: %s", absent, body)
		}
	}
	if req.ProfileID != "isoMdl" {
		t.Errorf("ProfileID = %q, want isoMdl", req.ProfileID)
	}
	if req.AuthMethod != "PRE_AUTHORIZED" {
		t.Errorf("AuthMethod = %q, want PRE_AUTHORIZED", req.AuthMethod)
	}
}

func TestMdocNamespaceFor(t *testing.T) {
	tests := []struct{ in, want string }{
		{"org.iso.18013.5.1.mDL", "org.iso.18013.5.1"},
		{"org.iso.23220.photoID.1", "org.iso.23220.photoID"},
		{"nodots", "nodots"},
	}
	for _, tt := range tests {
		if got := mdocNamespaceFor(tt.in); got != tt.want {
			t.Errorf("mdocNamespaceFor(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIssuer2OfferResponseParsing(t *testing.T) {
	// issuer-api2 returns JSON; the legacy issuer-api returns a bare string.
	// Parsing the wrong one yields an offer URI of "" and a QR that opens
	// nothing, so pin the shape.
	body := []byte(`{"offerId":"abc-123","profileId":"isoMdl","credentialOffer":"openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.org%2Foffer%3Fid%3Dabc-123"}`)

	var resp issuer2OfferResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OfferID != "abc-123" {
		t.Errorf("OfferID = %q, want abc-123", resp.OfferID)
	}
	if !strings.HasPrefix(resp.CredentialOffer, "openid-credential-offer://") {
		t.Errorf("CredentialOffer = %q, want an openid-credential-offer:// URI", resp.CredentialOffer)
	}
}
