package waltid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/mdoc"
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
		{"org.iso.23220.photoid.1", "isoPhotoId", "org.iso.23220.1", true},
		// Wrong case must NOT resolve: docTypeProfiles is an exact-match
		// allowlist against issuer2-profiles.conf's credentialConfigurationId,
		// which spells this docType lowercase ("photoid", not "photoID").
		{"org.iso.23220.photoID.1", "", "", false},
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

// TestKnownDocTypesResolveInProfiles pins the mdoc catalog (what the operator
// sees in the schema builder) against docTypeProfiles (what issuer-api2 can
// actually resolve). This is the guard that would have caught the
// photoID/photoid casing mismatch automatically: every docType offered in
// the builder MUST resolve to a profile here, or an operator can build and
// save a schema that fails at issuance time — a failure that surfaces late
// and looks like an infrastructure fault rather than a UI bug.
func TestKnownDocTypesResolveInProfiles(t *testing.T) {
	for _, d := range mdoc.KnownDocTypes() {
		if _, ok := profileIDForDocType(d.DocType); !ok {
			t.Errorf("mdoc.KnownDocTypes() offers docType %q but docTypeProfiles has no entry for it — "+
				"an operator could build and save this schema, then have issuance fail", d.DocType)
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

// TestIssueToWallet_MdocDoesNotRequireLegacyIssuer proves the mso_mdoc
// dispatch happens before ensureIssuerKey and the legacy configID
// resolution, not inside the shared format switch below them. Before this
// fix, IssueToWallet called ensureIssuerKey unconditionally at the top of
// the function; with IssuerBaseURL empty (a.issuer == nil) that fails with
// "waltid: issuer role not configured (issuerBaseUrl missing)" — pointing
// whoever's debugging at the legacy service when the actual dependency for
// mso_mdoc is issuer-api2. An mdoc-only deployment (real: Task 2's
// issuer-api2 is meant to run without the legacy issuer-api at all) would
// hit that misleading error on every issuance despite being configured
// correctly for the format it's actually using.
//
// This test leaves IssuerBaseURL empty and Issuer2BaseURL pointed at a fake
// issuer-api2 server that returns a real offer. If the old ordering were
// still in place, this would fail with the legacy "issuer role not
// configured" error before ever reaching issuer-api2's handler; with the
// fix, issuance succeeds using only the issuer2 client.
func TestIssueToWallet_MdocDoesNotRequireLegacyIssuer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issuer2/credential-offers" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(issuer2OfferResponse{
			OfferID:         "offer-1",
			CredentialOffer: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.org%2Foffer",
		})
	}))
	defer srv.Close()

	a, err := New(Config{
		// IssuerBaseURL deliberately empty: a.issuer stays nil. If the
		// mso_mdoc path still depended on ensureIssuerKey/a.issuer, this
		// would fail with the legacy "issuer role not configured" error
		// instead of reaching issuer-api2.
		VerifierBaseURL: "http://verifier.invalid",
		Issuer2BaseURL:  srv.URL,
	}, "Walt Community Stack")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema: vctypes.Schema{
			ID:   "org.iso.18013.5.1.mDL",
			Std:  "mso_mdoc",
			Name: "Driver's Licence",
		},
		SubjectData: map[string]string{"family_name": "Perez"},
		Flow:        "pre_auth",
	})
	if err != nil {
		t.Fatalf("IssueToWallet: %v (want success via issuer-api2, not a legacy-issuer error)", err)
	}
	if res.OfferID != "offer-1" {
		t.Errorf("OfferID = %q, want offer-1", res.OfferID)
	}
	if !strings.HasPrefix(res.OfferURI, "openid-credential-offer://") {
		t.Errorf("OfferURI = %q, want an openid-credential-offer:// URI", res.OfferURI)
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
