package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// B2/1B: a SD-JWT schema that ALSO lists statusIdx/statusUri as fields must not
// produce duplicate view columns (the CREATE VIEW crash).
func TestBuildAuthcodeArtifacts_NoDuplicateStatusColumns(t *testing.T) {
	schema := vctypes.Schema{
		ID: "DupTest", Name: "DupTest", Std: "sd_jwt_vc (IETF)", Custom: true,
		AdditionalTypes: []string{"DupTest"},
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "onBehalfOf"}, {Name: "statusUri"}, {Name: "statusIdx"}, {Name: "statusType"},
		},
	}
	art := buildAuthcodeArtifacts(schema, "https://example.test/status-list/token/v1")
	if n := strings.Count(art.viewDDL, `AS "statusIdx"`); n != 1 {
		t.Fatalf("statusIdx column count = %d, want 1:\n%s", n, art.viewDDL)
	}
	if n := strings.Count(art.viewDDL, `AS "statusUri"`); n != 1 {
		t.Fatalf("statusUri column count = %d, want 1:\n%s", n, art.viewDDL)
	}
}

// B7: the temporal gate downgrades Valid for out-of-window credentials.
func TestAttachTemporalVerdict(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cred := func(raw map[string]any) backend.NormalizedCredential {
		return backend.NormalizedCredential{Types: []string{"TestCred"}, Raw: raw}
	}

	expired := &backend.VerificationResult{Valid: true, Credentials: []backend.NormalizedCredential{
		cred(map[string]any{"validUntil": "2020-01-01T00:00:00Z"})}}
	attachTemporalVerdict(expired, now, nil)
	if expired.Valid || !strings.Contains(expired.Method, "expired") {
		t.Fatalf("expired must downgrade Valid with reason; got valid=%v method=%q", expired.Valid, expired.Method)
	}

	notYet := &backend.VerificationResult{Valid: true, Credentials: []backend.NormalizedCredential{
		cred(map[string]any{"validFrom": "2030-01-01T00:00:00Z"})}}
	attachTemporalVerdict(notYet, now, nil)
	if notYet.Valid || !strings.Contains(notYet.Method, "not yet valid") {
		t.Fatalf("not-yet-valid must downgrade Valid; got valid=%v method=%q", notYet.Valid, notYet.Method)
	}

	within := &backend.VerificationResult{Valid: true, Credentials: []backend.NormalizedCredential{
		cred(map[string]any{"validFrom": "2020-01-01T00:00:00Z", "validUntil": "2030-01-01T00:00:00Z"})}}
	attachTemporalVerdict(within, now, nil)
	if !within.Valid {
		t.Fatalf("within-window must stay Valid; method=%q", within.Method)
	}

	none := &backend.VerificationResult{Valid: true, Credentials: []backend.NormalizedCredential{cred(map[string]any{})}}
	attachTemporalVerdict(none, now, nil)
	if !none.Valid {
		t.Fatal("no temporal bounds must stay Valid (no constraint)")
	}

	// Pre-existing Method is appended to (not overwritten); a credential with no
	// Types uses the generic "credential" label.
	withMethod := &backend.VerificationResult{Valid: true, Method: "OID4VP", Credentials: []backend.NormalizedCredential{
		{Raw: map[string]any{"validUntil": "2020-01-01T00:00:00Z"}}}}
	attachTemporalVerdict(withMethod, now, nil)
	if withMethod.Valid || !strings.Contains(withMethod.Method, "OID4VP · ") || !strings.Contains(withMethod.Method, "credential has expired") {
		t.Fatalf("expected appended reason with generic label; got valid=%v method=%q", withMethod.Valid, withMethod.Method)
	}
}

// B3: issuance-time validity input normalization.
func TestNormalizeIssuanceTime(t *testing.T) {
	if got := normalizeIssuanceTime(""); got != "" {
		t.Fatalf("empty: got %q", got)
	}
	if got := normalizeIssuanceTime("garbage"); got != "" {
		t.Fatalf("garbage: got %q", got)
	}
	for _, in := range []string{"2026-07-06T14:30:00Z", "2026-07-06T14:30", "2026-07-06"} {
		got := normalizeIssuanceTime(in)
		if !strings.HasPrefix(got, "2026-07-06") {
			t.Fatalf("normalizeIssuanceTime(%q) = %q, want a 2026-07-06 timestamp", in, got)
		}
		if _, err := time.Parse(time.RFC3339, got); err != nil {
			t.Fatalf("output %q is not RFC3339: %v", got, err)
		}
	}
}

// B5: the two-step picker state machine — reset and a card click are mutually
// exclusive, so a "change" chip (which hx-includes a stale schema_id) clears the
// slot instead of re-selecting it; a step-2 click replaces the identity.
func TestApplyDelegationPick(t *testing.T) {
	d, s := applyDelegationPick("", "", "", "", "deleg-1")
	if d != "deleg-1" || s != "" {
		t.Fatalf("step1 pick: (%q,%q)", d, s)
	}
	d, s = applyDelegationPick("deleg-1", "", "", "", "id-1")
	if d != "deleg-1" || s != "id-1" {
		t.Fatalf("step2 pick: (%q,%q)", d, s)
	}
	d, s = applyDelegationPick("deleg-1", "id-1", "", "", "id-2")
	if d != "deleg-1" || s != "id-2" {
		t.Fatalf("step2 replace-on-click: (%q,%q)", d, s)
	}
	// The B5 bug: reset must win over the hx-included stale schema_id.
	d, s = applyDelegationPick("deleg-1", "id-1", "1", "", "stale")
	if d != "" || s != "" {
		t.Fatalf("reset_deleg must clear BOTH ignoring stale schema_id: (%q,%q)", d, s)
	}
	d, s = applyDelegationPick("deleg-1", "id-1", "", "1", "stale")
	if d != "deleg-1" || s != "" {
		t.Fatalf("reset_subject must clear identity only: (%q,%q)", d, s)
	}
	d, s = applyDelegationPick("deleg-1", "id-1", "", "", "")
	if d != "deleg-1" || s != "id-1" {
		t.Fatalf("no action -> unchanged: (%q,%q)", d, s)
	}
}
