package waltid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
		// mDL's profileID is deliberately "": docTypeProfiles' mDL entry is
		// allowlist membership + namespace only. "isoMdl" no longer exists in
		// the HOCON — real issuance dispatches through
		// mdlProfileForCategoryCount (isoMdl_1cat..isoMdl_4cat), never through
		// this map's profileID for mDL. Pinning "" here catches a future
		// caller that assumes this profileID is postable.
		{"org.iso.18013.5.1.mDL", "", "org.iso.18013.5.1", true},
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

// TestBuilderSavedMdocSchemaResolvesProfile is the issuance-side half of the
// C1 guard. TestKnownDocTypesResolveInProfiles above checks the CATALOG
// (mdoc.KnownDocTypes) against the profile table, but that says nothing about
// whether the docType actually survives the schema builder's save — and for a
// while it did not: currentBuilderSchema dropped it, so every builder-made
// mdoc schema reached issuance carrying its generated "custom-<nano>" ID and
// failed with `no issuer-api2 profile for docType "custom-..."`. That made
// TestKnownDocTypesResolveInProfiles false assurance: green while the real
// path was broken.
//
// This test reconstructs the schema shape the builder now saves — the docType
// in AdditionalTypes[0], and the catalog's "<docType>_mso_mdoc" configID as
// the ID — and runs it through the same mdocDocTypeFor + profileIDForDocType
// pair that buildIssuer2Offer uses.
//
// The regression guard is the "custom-..." sub-case: it pins that the broken
// shape genuinely does NOT resolve, so this test cannot silently pass if the
// docType is dropped again.
func TestBuilderSavedMdocSchemaResolvesProfile(t *testing.T) {
	for _, d := range mdoc.KnownDocTypes() {
		schema := vctypes.Schema{
			// What appendCredentialType/customSchemaTypeName produce from
			// AdditionalTypes[0] for an mso_mdoc schema.
			ID:              d.DocType + "_mso_mdoc",
			Std:             "mso_mdoc",
			Name:            d.Name,
			Custom:          true,
			AdditionalTypes: []string{d.DocType},
		}
		docType := mdocDocTypeFor(schema)
		if docType != d.DocType {
			t.Errorf("mdocDocTypeFor(builder-saved %s) = %q, want %q", d.Name, docType, d.DocType)
			continue
		}
		if _, ok := profileIDForDocType(docType); !ok {
			t.Errorf("a builder-saved schema for %q does not resolve to an issuer-api2 profile — "+
				"the operator's docType is not reaching issuance", d.DocType)
		}
	}

	// The pre-fix shape must NOT resolve. Without this, the assertions above
	// could pass against broken code that happened to route some other way.
	broken := vctypes.Schema{
		ID:              "custom-dkv4qjt53fua",
		Std:             "mso_mdoc",
		Name:            "Licencia",
		Custom:          true,
		AdditionalTypes: []string{},
	}
	if _, ok := profileIDForDocType(mdocDocTypeFor(broken)); ok {
		t.Error("a schema that dropped its docType resolved to a profile — the C1 guard above proves nothing")
	}
}

// A field the caller omits must NOT appear in the request at all. issuer-api2
// merges runtimeOverrides recursively over the profile, so any key we send
// wins but any key we omit keeps the profile's value. The versioned profile
// has its sample data emptied precisely so an omission surfaces as blank —
// but if we were to send a key with a zero value we would be asserting that
// blank on purpose, and if we send nothing the profile decides. This test
// pins the boundary: only what the operator actually filled in gets sent.
//
// Sends one real driving_privileges entry (not zero) so this test exercises
// field omission without colliding with the separate 0-categories rejection
// covered by TestBuildIssuer2OfferRejectsZeroDrivingPrivileges.
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
	privileges, err := mdoc.EncodeDrivingPrivileges([]mdoc.DrivingPrivilege{
		{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	structured := map[string]json.RawMessage{"driving_privileges": privileges}

	req, err := buildIssuer2Offer(schema, subject, structured)
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
	if req.ProfileID != "isoMdl_1cat" {
		t.Errorf("ProfileID = %q, want isoMdl_1cat", req.ProfileID)
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

	privileges, err := mdoc.EncodeDrivingPrivileges([]mdoc.DrivingPrivilege{
		{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}

	res, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema: vctypes.Schema{
			ID:   "org.iso.18013.5.1.mDL",
			Std:  "mso_mdoc",
			Name: "Driver's Licence",
		},
		SubjectData:    map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{"driving_privileges": privileges},
		Flow:           "pre_auth",
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

// TestMdocDocTypeForSavedBuilderSchema reproduces a real deployment failure:
// issuing a builder-made mDL died with
//
//	no issuer-api2 profile for docType "custom-dkv6iyntczt6"
//
// SaveCustomSchema persists a custom schema under its generated "custom-<nano>"
// ID, so BaseType() — which derives from Schema.ID — yields that ID, not the
// docType. The operator's selection only survives in AdditionalTypes, so that
// is what mdocDocTypeFor must consult first.
func TestMdocDocTypeForSavedBuilderSchema(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		schema     vctypes.Schema
	}{
		{
			name: "saved builder mDL keeps its generated ID",
			want: "org.iso.18013.5.1.mDL",
			schema: vctypes.Schema{
				ID:              "custom-dkv6iyntczt6",
				Std:             "mso_mdoc",
				Custom:          true,
				AdditionalTypes: []string{"org.iso.18013.5.1.mDL"},
			},
		},
		{
			name: "saved builder Photo ID",
			want: "org.iso.23220.photoid.1",
			schema: vctypes.Schema{
				ID:              "custom-abc123",
				Std:             "mso_mdoc",
				Custom:          true,
				AdditionalTypes: []string{"org.iso.23220.photoid.1"},
			},
		},
		{
			name:   "stock catalog entry still resolves via BaseType",
			want:   "org.iso.18013.5.1.mDL",
			schema: vctypes.Schema{ID: "org.iso.18013.5.1.mDL_mso_mdoc", Std: "mso_mdoc"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mdocDocTypeFor(tc.schema)
			if got != tc.want {
				t.Errorf("mdocDocTypeFor() = %q, want %q", got, tc.want)
			}
			if _, ok := profileIDForDocType(got); !ok {
				t.Errorf("docType %q does not resolve to an issuer-api2 profile", got)
			}
		})
	}
}

func TestMdlProfileForCategoryCount(t *testing.T) {
	tests := []struct {
		n             int
		wantProfileID string
		wantOK        bool
	}{
		{0, "", false},
		{1, "isoMdl_1cat", true},
		{2, "isoMdl_2cat", true},
		{3, "isoMdl_3cat", true},
		{4, "isoMdl_4cat", true},
		{5, "", false},
		{-1, "", false},
	}
	for _, tt := range tests {
		got, ok := mdlProfileForCategoryCount(tt.n)
		if got.profileID != tt.wantProfileID || ok != tt.wantOK {
			t.Errorf("mdlProfileForCategoryCount(%d) = (%+v, %v), want (profileID=%q, %v)",
				tt.n, got, ok, tt.wantProfileID, tt.wantOK)
		}
		if ok && got.baseNamespace != "org.iso.18013.5.1" {
			t.Errorf("mdlProfileForCategoryCount(%d).baseNamespace = %q, want org.iso.18013.5.1", tt.n, got.baseNamespace)
		}
	}
}

// TestBuildIssuer2OfferSelectsProfileByCategoryCount is the integration
// point between mdlProfileForCategoryCount and buildIssuer2Offer: the
// caller passes real driving_privileges via StructuredData, and the
// resulting ProfileID must match that exact count — never a fixed
// "isoMdl", and never padded to a different count.
func TestBuildIssuer2OfferSelectsProfileByCategoryCount(t *testing.T) {
	schema := vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc", Name: "Driver's Licence"}
	subject := map[string]string{"family_name": "Perez", "given_name": "Ana"}

	for n := 1; n <= mdoc.DrivingPrivilegesMaxCategories; n++ {
		privileges := make([]mdoc.DrivingPrivilege, n)
		for i := range privileges {
			privileges[i] = mdoc.DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"}
		}
		raw, err := mdoc.EncodeDrivingPrivileges(privileges)
		if err != nil {
			t.Fatalf("n=%d: EncodeDrivingPrivileges: %v", n, err)
		}
		structured := map[string]json.RawMessage{"driving_privileges": raw}

		req, err := buildIssuer2Offer(schema, subject, structured)
		if err != nil {
			t.Fatalf("n=%d: buildIssuer2Offer: %v", n, err)
		}
		wantProfileID := fmt.Sprintf("isoMdl_%dcat", n)
		if req.ProfileID != wantProfileID {
			t.Errorf("n=%d: ProfileID = %q, want %q", n, req.ProfileID, wantProfileID)
		}

		ns := req.RuntimeOverrides.CredentialData["org.iso.18013.5.1"]
		arr, ok := ns["driving_privileges"].([]any)
		if !ok {
			t.Fatalf("n=%d: driving_privileges is %T, want []any", n, ns["driving_privileges"])
		}
		if len(arr) != n {
			t.Errorf("n=%d: driving_privileges has %d entries, want exactly %d — no padding", n, len(arr), n)
		}
	}
}

// TestBuildIssuer2OfferRejectsZeroDrivingPrivileges is the negative case:
// driving_privileges is a MANDATORY ISO 18013-5 Table 3 element for mDL,
// so 0 real categories must be a hard error, never silently accepted or
// defaulted to some profile.
func TestBuildIssuer2OfferRejectsZeroDrivingPrivileges(t *testing.T) {
	schema := vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc", Name: "Driver's Licence"}
	subject := map[string]string{"family_name": "Perez", "given_name": "Ana"}

	if _, err := buildIssuer2Offer(schema, subject, nil); err == nil {
		t.Error("buildIssuer2Offer with no driving_privileges at all returned no error, want a rejection")
	}

	empty, err := mdoc.EncodeDrivingPrivileges(nil)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges(nil): %v", err)
	}
	if empty != nil {
		t.Fatalf("EncodeDrivingPrivileges(nil) = %s, want nil", empty)
	}
	// empty is nil, so this reproduces the "field never sent" case, same as above.
}

// TestIssuer2OfferCarriesDrivingPrivilegesAsJSONArray asserts on the ACTUAL
// HTTP body that reaches issuer-api2, captured from a live handler rather
// than from the in-memory struct.
//
// This is the adapter-level half of the F4 regression. The wire body is what
// walt.id parses, and the failure was a type error in exactly that body:
// `"driving_privileges": "1"` instead of `"driving_privileges": [ {...} ]`.
// The check unmarshals and asserts the Go type, because a stringified array
// contains every substring a Contains() assertion would look for.
func TestIssuer2OfferCarriesDrivingPrivilegesAsJSONArray(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(issuer2OfferResponse{
			OfferID:         "offer-dp",
			CredentialOffer: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.org%2Foffer",
		})
	}))
	defer srv.Close()

	a, err := New(Config{VerifierBaseURL: "http://verifier.invalid", Issuer2BaseURL: srv.URL}, "Walt Community Stack")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	privileges, err := mdoc.EncodeDrivingPrivileges([]mdoc.DrivingPrivilege{
		{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"},
		{VehicleCategoryCode: "C1", IssueDate: "2022-09-15", ExpiryDate: "2032-09-15"},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}

	if _, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema: vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc", Name: "Driver's Licence"},
		SubjectData: map[string]string{
			"family_name":     "Perez",
			"given_name":      "Ana",
			"document_number": "DL-99887",
		},
		StructuredData: map[string]json.RawMessage{"driving_privileges": privileges},
	}); err != nil {
		t.Fatalf("IssueToWallet: %v", err)
	}

	var body struct {
		RuntimeOverrides struct {
			CredentialData map[string]map[string]any `json:"credentialData"`
		} `json:"runtimeOverrides"`
	}
	if err := json.Unmarshal(captured, &body); err != nil {
		t.Fatalf("parse captured request: %v (body=%s)", err, captured)
	}
	ns := body.RuntimeOverrides.CredentialData["org.iso.18013.5.1"]
	if ns == nil {
		t.Fatalf("no org.iso.18013.5.1 namespace in the request: %s", captured)
	}

	arr, isArray := ns["driving_privileges"].([]any)
	if !isArray {
		t.Fatalf("driving_privileges reached walt.id as %T, want []any.\n"+
			"This is F4: walt.id rejects it at wallet redemption with "+
			"\"Expected to execute conversion from json array, but input |...| is not a json array\".\n"+
			"wire body: %s", ns["driving_privileges"], captured)
	}
	if len(arr) != 2 {
		t.Errorf("driving_privileges length = %d, want 2 (the real count this test submitted, no padding)",
			len(arr))
	}

	// Flat fields must be untouched by the map[string]any widening: they are
	// still plain JSON strings, exactly as before.
	if s, ok := ns["family_name"].(string); !ok || s != "Perez" {
		t.Errorf("family_name = %v (%T), want the string \"Perez\" — "+
			"widening the value type must not have changed how flat fields marshal",
			ns["family_name"], ns["family_name"])
	}
}

// A portrait must reach walt.id as a plain base64 STRING: its profile entry
// declares conversionType "base64StringToByteString" and does the CBOR
// byte-string conversion itself. Sending anything else (bytes, an object)
// would break that conversion — and encoding CBOR ourselves would cross the
// mediator boundary.
func TestIssuer2OfferCarriesPortraitAsBase64String(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(issuer2OfferResponse{
			OfferID:         "offer-p",
			CredentialOffer: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.org%2Foffer",
		})
	}))
	defer srv.Close()

	a, err := New(Config{VerifierBaseURL: "http://verifier.invalid", Issuer2BaseURL: srv.URL}, "Walt Community Stack")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	privileges, err := mdoc.EncodeDrivingPrivileges([]mdoc.DrivingPrivilege{
		{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}

	const portrait = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNiAAAABgADNjd8qAAAAABJRU5ErkJggg=="
	if _, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema:         vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc", Name: "Driver's Licence"},
		SubjectData:    map[string]string{"portrait": portrait},
		StructuredData: map[string]json.RawMessage{"driving_privileges": privileges},
	}); err != nil {
		t.Fatalf("IssueToWallet: %v", err)
	}

	var body struct {
		RuntimeOverrides struct {
			CredentialData map[string]map[string]any `json:"credentialData"`
		} `json:"runtimeOverrides"`
	}
	if err := json.Unmarshal(captured, &body); err != nil {
		t.Fatalf("parse captured request: %v (body=%s)", err, captured)
	}
	got, ok := body.RuntimeOverrides.CredentialData["org.iso.18013.5.1"]["portrait"].(string)
	if !ok {
		t.Fatalf("portrait is not a JSON string: %s", captured)
	}
	if got != portrait {
		t.Errorf("portrait was altered in transit:\ngot  %.40s…\nwant %.40s…", got, portrait)
	}
	if strings.HasPrefix(got, "data:") {
		t.Errorf("portrait carries a data: URI prefix — base64StringToByteString would decode it as image data")
	}
}

// TestBlankDatesNeverReachWaltid reproduces the failure an operator hit twice
// on a live deployment: leaving an optional date blank made issuance die on
// the citizen's PHONE, long after the offer had returned HTTP 201, with
//
//	java.time.format.DateTimeParseException: Text '' could not be parsed
//
// The cause is not our blank — it is that omitting the field lets issuer-api2's
// deep merge keep the PROFILE's empty string, which its stringToFullDate
// mapping then cannot parse. Confirmed against a live issuer-api2: the same
// payload with issue_date omitted returns 400 at redemption, and with it
// present returns 200.
func TestBlankDatesNeverReachWaltid(t *testing.T) {
	schema := vctypes.Schema{
		ID:              "custom-x",
		Std:             "mso_mdoc",
		Custom:          true,
		AdditionalTypes: []string{"org.iso.18013.5.1.mDL"},
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "family_name", Datatype: "string"},
			{Name: "birth_date", Datatype: "string", Format: "date"},
			{Name: "issue_date", Datatype: "string", Format: "date"},
			{Name: "portrait_capture_date", Datatype: "string", Format: "date"},
		},
	}
	// The operator filled the name and birth date, left the other two blank.
	subject := map[string]string{
		"family_name": "Alvarez",
		"birth_date":  "1990-05-14",
		"issue_date":  "",
	}
	privileges, err := mdoc.EncodeDrivingPrivileges([]mdoc.DrivingPrivilege{
		{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	structured := map[string]json.RawMessage{"driving_privileges": privileges}

	req, err := buildIssuer2Offer(schema, subject, structured)
	if err != nil {
		t.Fatalf("buildIssuer2Offer: %v", err)
	}
	data := req.RuntimeOverrides.CredentialData["org.iso.18013.5.1"]

	for _, f := range schema.FieldsSpec {
		if f.Format != "date" {
			continue
		}
		v, present := data[f.Name]
		if !present {
			t.Errorf("%s omitted — the profile's blank survives the merge and kills "+
				"issuance at wallet redemption", f.Name)
			continue
		}
		s, _ := v.(string)
		if strings.TrimSpace(s) == "" {
			t.Errorf("%s sent as %q — an empty date is what walt.id cannot parse", f.Name, s)
		}
	}

	// The operator's own value must never be overwritten by a fallback.
	if got := data["birth_date"]; got != "1990-05-14" {
		t.Errorf("birth_date = %v, want the operator's value 1990-05-14", got)
	}
	// portrait_capture_date derives from issue_date rather than inventing a
	// date unrelated to the credential.
	if data["portrait_capture_date"] != data["issue_date"] {
		t.Errorf("portrait_capture_date = %v, want it to match issue_date %v",
			data["portrait_capture_date"], data["issue_date"])
	}
}
