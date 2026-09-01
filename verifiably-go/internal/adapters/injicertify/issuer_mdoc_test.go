package injicertify

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

// TestIssueToWalletMdocCarriesDrivingPrivilegesFromStructuredData pins that
// IssueToWallet reads driving_privileges from StructuredData (not just
// SubjectData) for mso_mdoc schemas in ModePreAuth, and that every count from
// 1 to the ceiling reaches the POSTed claims intact — NESTED under the ISO
// namespace, not flat. Confirmed live against a real Inji Certify v0.14.0:
// flat claims made PreAuthorizedCodeService.validateClaimsWithMandatory
// reject every single field as "unknown_claims" at once, because
// config.getClaims() for mso_mdoc returns credential_config.mso_mdoc_claims
// verbatim — a map with exactly one top-level key, the namespace — so a flat
// posted claim can never match it.
func TestIssueToWalletMdocCarriesDrivingPrivilegesFromStructuredData(t *testing.T) {
	for n := 1; n <= mdoc.DrivingPrivilegesMaxCategories; n++ {
		var gotClaims map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body preAuthorizedDataRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotClaims = body.Claims
			_ = json.NewEncoder(w).Encode(preAuthorizedDataResponse{
				CredentialOfferURI: "openid-credential-offer://?credential_offer=%7B%7D",
			})
		}))
		defer srv.Close()

		a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL, PublicBaseURL: srv.URL}, "Inji Certify · Pre-Auth")
		if err != nil {
			t.Fatalf("n=%d: New: %v", n, err)
		}

		privileges := make([]mdoc.DrivingPrivilege, n)
		for i := range privileges {
			privileges[i] = mdoc.DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"}
		}
		raw, err := mdoc.EncodeDrivingPrivileges(privileges)
		if err != nil {
			t.Fatalf("n=%d: EncodeDrivingPrivileges: %v", n, err)
		}

		req := backend.IssueRequest{
			Schema:         vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
			SubjectData:    map[string]string{"family_name": "Perez"},
			StructuredData: map[string]json.RawMessage{"driving_privileges": raw},
		}
		if _, err := a.IssueToWallet(context.Background(), req); err != nil {
			t.Fatalf("n=%d: IssueToWallet: %v", n, err)
		}

		ns, ok := gotClaims["org.iso.18013.5.1"].(map[string]any)
		if !ok {
			t.Fatalf("n=%d: claims[\"org.iso.18013.5.1\"] is %T, want map[string]any — claims must be nested under the ISO namespace for mso_mdoc, not flat (Inji Certify rejects flat mso_mdoc claims as unknown_claims)", n, gotClaims["org.iso.18013.5.1"])
		}
		if _, flatLeak := gotClaims["driving_privileges"]; flatLeak {
			t.Errorf("n=%d: claims[\"driving_privileges\"] present at the TOP level too — must appear ONLY inside the namespace, never flat", n)
		}
		// Posted as a raw JSON STRING, not a decoded array — confirmed live
		// against Inji Certify v0.14.0 that posting a real array makes
		// Velocity substitute Java's List.toString() (unquoted, "="-separated)
		// for the template's unquoted ${driving_privileges} marker, which
		// fails org.json's own re-parse. Sending the already-serialized JSON
		// string instead — the same "cast array to text" trick the working
		// spike's PostgresDataProviderPlugin query used — makes Velocity
		// substitute valid JSON verbatim. See issuer.go's comment at this
		// same assignment for the full trace.
		dpRaw, ok := ns["driving_privileges"].(string)
		if !ok {
			t.Fatalf("n=%d: claims[\"org.iso.18013.5.1\"][\"driving_privileges\"] is %T, want string (a pre-serialized JSON array) — StructuredData was not read, or was decoded instead of kept as a raw string", n, ns["driving_privileges"])
		}
		var dp []any
		if err := json.Unmarshal([]byte(dpRaw), &dp); err != nil {
			t.Fatalf("n=%d: driving_privileges string is not valid JSON: %v (got: %s)", n, err, dpRaw)
		}
		if len(dp) != n {
			t.Errorf("n=%d: driving_privileges has %d entries, want exactly %d", n, len(dp), n)
		}
		if familyName, _ := ns["family_name"].(string); familyName != "Perez" {
			t.Errorf("n=%d: claims[\"org.iso.18013.5.1\"][\"family_name\"] = %q, want %q — SubjectData fields must be nested too, not just driving_privileges", n, familyName, "Perez")
		}
	}
}

func TestIssueToWalletMdocRejectsZeroDrivingPrivileges(t *testing.T) {
	a, err := New(Config{Mode: ModePreAuth, BaseURL: "http://unused-if-guard-works", PublicBaseURL: "http://unused"}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
		SubjectData: map[string]string{"family_name": "Perez"},
		// StructuredData sin driving_privileges en absoluto.
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with no driving_privileges returned no error, want a rejection — never call the network")
	}
}

func TestIssueToWalletMdocRejectsOverCapDrivingPrivileges(t *testing.T) {
	a, err := New(Config{Mode: ModePreAuth, BaseURL: "http://unused-if-guard-works", PublicBaseURL: "http://unused"}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
		SubjectData: map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{
			// Construido directamente como JSON crudo, SIN pasar por
			// mdoc.EncodeDrivingPrivileges (que ya trunca a 4 por su
			// cuenta) — así se reproduce "más de 4 llegó al adapter", no
			// "el encoder ya lo truncó", para que el guard del adapter sea
			// lo que realmente se está probando.
			"driving_privileges": mustMarshalNPrivileges(mdoc.DrivingPrivilegesMaxCategories + 1),
		},
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with 5 driving_privileges returned no error, want a rejection — never call the network")
	}
}

// TestIssueToWalletPhotoIDDoesNotRequireDrivingPrivileges reproduces a real
// bug found live: issuing a Photo ID credential (org.iso.23220.photoid.1 —
// a legitimate mso_mdoc docType, per mdoc.KnownDocTypes) in ModePreAuth,
// with StructuredData carrying NO driving_privileges at all — correct,
// since ISO/IEC 23220-1's Photo ID has no such element — was unconditionally
// rejected with "driving_privileges es obligatorio en ISO 18013-5", the
// exact same error a genuinely-invalid mDL submission gets. The guard above
// checked only Std=="mso_mdoc" (the shared CONTAINER format for every ISO
// docType this system issues), not which docType was actually being issued,
// so it fired for a docType the standard never asked this element of.
func TestIssueToWalletPhotoIDDoesNotRequireDrivingPrivileges(t *testing.T) {
	var gotClaims map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body preAuthorizedDataRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotClaims = body.Claims
		_ = json.NewEncoder(w).Encode(preAuthorizedDataResponse{
			CredentialOfferURI: "openid-credential-offer://?credential_offer=%7B%7D",
		})
	}))
	defer srv.Close()

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL, PublicBaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-photoid", Std: "mso_mdoc", AdditionalTypes: []string{mdoc.PhotoIDDocType}},
		SubjectData: map[string]string{"family_name": "Perez"},
		// StructuredData sin driving_privileges — correcto para Photo ID,
		// que no tiene ese elemento en absoluto.
	}
	if _, err := a.IssueToWallet(context.Background(), req); err != nil {
		t.Fatalf("IssueToWallet for Photo ID should not require driving_privileges, got error: %v", err)
	}
	// org.iso.23220.1, NOT org.iso.23220.photoid: Photo ID's real ISO base
	// namespace, resolved via mdoc.NamespaceForDocType — the dot-stripping
	// heuristic this test used to assert on (before that helper existed)
	// gives the wrong namespace for this exact docType. See
	// mdoc.NamespaceForDocType's own comment for why.
	ns, ok := gotClaims["org.iso.23220.1"].(map[string]any)
	if !ok {
		t.Fatalf("claims[%q] is %T, want map[string]any", "org.iso.23220.1", gotClaims["org.iso.23220.1"])
	}
	if _, present := ns["driving_privileges"]; present {
		t.Errorf("driving_privileges present in Photo ID claims — must never appear for this docType")
	}
}

// TestIssueToWalletMDLStillRequiresDrivingPrivileges is the inverse safety
// check for the same fix: mDL's own guard must still fire when
// driving_privileges is missing. The fix narrows the guard from "any
// mso_mdoc schema" to "mso_mdoc AND docType==mDL specifically" — it must
// not accidentally narrow it out of existence for mDL itself.
func TestIssueToWalletMDLStillRequiresDrivingPrivileges(t *testing.T) {
	a, err := New(Config{Mode: ModePreAuth, BaseURL: "http://unused-if-guard-works", PublicBaseURL: "http://unused"}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{mdoc.MDLDocType}},
		SubjectData: map[string]string{"family_name": "Perez"},
		// StructuredData sin driving_privileges en absoluto — mDL debe seguir
		// rechazando esto.
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet for mDL with no driving_privileges returned no error, want a rejection — the fix must not have weakened mDL's own guard")
	}
}

func mustMarshalNPrivileges(n int) json.RawMessage {
	out := make([]map[string]string, n)
	for i := range out {
		out[i] = map[string]string{"vehicle_category_code": "B", "issue_date": "2021-06-01", "expiry_date": "2031-06-01"}
	}
	raw, _ := json.Marshal(out)
	return raw
}

// TestIssueToWalletMdocGuardDoesNotApplyToAuthCode confirms the mdoc guard
// is scoped to ModePreAuth only, per this task's explicit gating
// requirement — a schema with Std=="mso_mdoc" reaching an Auth-Code-mode
// adapter must fall through to the EXISTING auth_code offer construction
// unmodified (which never reads claims/driving_privileges at all), not be
// rejected by the new mdoc-specific error messages.
func TestIssueToWalletMdocGuardDoesNotApplyToAuthCode(t *testing.T) {
	a, err := New(Config{Mode: ModeAuthCode, BaseURL: "http://unused", PublicBaseURL: "http://unused", AuthorizationServer: "http://unused"}, "Inji Certify · Auth-Code")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema: vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
		// Sin driving_privileges — si el guard mdoc se ejecutara aquí,
		// esto fallaría con "driving_privileges es obligatorio...". No
		// debe fallar por esa razón: ModeAuthCode construye su oferta
		// local sin tocar claims en absoluto.
	}
	res, err := a.IssueToWallet(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueToWallet in ModeAuthCode should not apply the mdoc guard, got error: %v", err)
	}
	if res.Flow != "auth_code" {
		t.Errorf("Flow = %q, want %q", res.Flow, "auth_code")
	}
}

// TestIssueToWalletSurfacesMosipErrorMessage pins that a
// /v1/certify/pre-authorized-data error response's human-readable
// ErrorMessage reaches the operator alongside the short ErrorCode, not
// silently dropped. Mirrors waltid/issuer2.go's posture of surfacing the
// service's own wording verbatim for debugging.
func TestIssueToWalletSurfacesMosipErrorMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(preAuthorizedDataResponse{
			Errors: []mosipError{{
				ErrorCode:    "ERROR_SIGNING_QR_DATA",
				ErrorMessage: "Error occurred while signing QR code data",
			}},
		})
	}))
	defer srv.Close()

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL, PublicBaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-abc", Std: "vc+sd-jwt"},
		SubjectData: map[string]string{"family_name": "Perez"},
	}
	_, err = a.IssueToWallet(context.Background(), req)
	if err == nil {
		t.Fatal("IssueToWallet with a MOSIP error response returned no error")
	}
	if !strings.Contains(err.Error(), "ERROR_SIGNING_QR_DATA") {
		t.Errorf("error %q does not contain the ErrorCode", err.Error())
	}
	if !strings.Contains(err.Error(), "Error occurred while signing QR code data") {
		t.Errorf("error %q does not contain MOSIP's ErrorMessage — this was silently dropped before the fix, "+
			"leaving only the opaque ErrorCode for whoever debugs an issuance failure", err.Error())
	}
}

// TestIssueToWalletHandlesMosipErrorWithoutMessage covers the ErrorMessage
// field being absent/empty — the error must still surface the ErrorCode
// alone, not produce a malformed "code: " suffix.
func TestIssueToWalletHandlesMosipErrorWithoutMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(preAuthorizedDataResponse{
			Errors: []mosipError{{ErrorCode: "UNKNOWN_ERROR"}},
		})
	}))
	defer srv.Close()

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL, PublicBaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-abc", Std: "vc+sd-jwt"},
		SubjectData: map[string]string{"family_name": "Perez"},
	}
	_, err = a.IssueToWallet(context.Background(), req)
	if err == nil {
		t.Fatal("IssueToWallet with a MOSIP error response returned no error")
	}
	if !strings.Contains(err.Error(), "UNKNOWN_ERROR") {
		t.Errorf("error %q does not contain the ErrorCode", err.Error())
	}
	if strings.HasSuffix(strings.TrimSpace(err.Error()), ":") {
		t.Errorf("error %q has a trailing ': ' from an empty ErrorMessage", err.Error())
	}
}

// TestIssueToWalletRejectsDrivingPrivilegesWithUnknownField pins the
// per-entry shape validation added alongside the count check: an entry
// carrying a key outside mdoc.DrivingPrivilege's three known fields must be
// rejected here — server-side — rather than reaching Inji Certify's Velocity
// template substitution as opaque, unvalidated content. Reachable the same
// way the count check is: a direct POST bypassing the issue form's own
// validateDrivingPrivilegesCount.
func TestIssueToWalletRejectsDrivingPrivilegesWithUnknownField(t *testing.T) {
	a, err := New(Config{Mode: ModePreAuth, BaseURL: "http://unused-if-guard-works", PublicBaseURL: "http://unused"}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw := json.RawMessage(`[{"vehicle_category_code":"B","not_a_real_field":"injected"}]`)
	req := backend.IssueRequest{
		Schema:         vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{mdoc.MDLDocType}},
		SubjectData:    map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{"driving_privileges": raw},
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with an unknown-field driving_privileges entry returned no error, want a rejection")
	}
}

// TestIssueToWalletRejectsDrivingPrivilegesWithBlankCategoryCode covers an
// entry that decodes fine but carries no vehicle_category_code — the one
// field ISO/IEC 18013-5 actually requires per entry.
func TestIssueToWalletRejectsDrivingPrivilegesWithBlankCategoryCode(t *testing.T) {
	a, err := New(Config{Mode: ModePreAuth, BaseURL: "http://unused-if-guard-works", PublicBaseURL: "http://unused"}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw := json.RawMessage(`[{"vehicle_category_code":"  "}]`)
	req := backend.IssueRequest{
		Schema:         vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{mdoc.MDLDocType}},
		SubjectData:    map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{"driving_privileges": raw},
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with a blank vehicle_category_code returned no error, want a rejection")
	}
}

// TestIssueToWalletAcceptsDrivingPrivilegesWithoutOptionalDates confirms the
// shape validation does not over-tighten: issue_date/expiry_date stay
// optional (mdoc.DrivingPrivilege's own omitempty), only
// vehicle_category_code and the absence of unknown fields are enforced.
func TestIssueToWalletAcceptsDrivingPrivilegesWithoutOptionalDates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(preAuthorizedDataResponse{
			CredentialOfferURI: "openid-credential-offer://?credential_offer=%7B%7D",
		})
	}))
	defer srv.Close()

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL, PublicBaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw := json.RawMessage(`[{"vehicle_category_code":"B"}]`)
	req := backend.IssueRequest{
		Schema:         vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{mdoc.MDLDocType}},
		SubjectData:    map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{"driving_privileges": raw},
	}
	if _, err := a.IssueToWallet(context.Background(), req); err != nil {
		t.Errorf("IssueToWallet with only vehicle_category_code set should succeed, got: %v", err)
	}
}
