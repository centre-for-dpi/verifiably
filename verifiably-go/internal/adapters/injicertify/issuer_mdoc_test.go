package injicertify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// TestIssueToWalletMdocCarriesDrivingPrivilegesFromStructuredData pins that
// IssueToWallet reads driving_privileges from StructuredData (not just
// SubjectData) for mso_mdoc schemas in ModePreAuth, and that every count from
// 1 to the ceiling reaches the POSTed claims intact.
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

		dp, ok := gotClaims["driving_privileges"].([]any)
		if !ok {
			t.Fatalf("n=%d: claims[driving_privileges] is %T, want []any — StructuredData was not read", n, gotClaims["driving_privileges"])
		}
		if len(dp) != n {
			t.Errorf("n=%d: driving_privileges has %d entries, want exactly %d", n, len(dp), n)
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
