// SPDX-License-Identifier: Apache-2.0

package cards

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

var at = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func sample() *resultsv1.VerificationResult {
	return &resultsv1.VerificationResult{
		Id:               "one",
		Verdict:          policyv1.EvaluateResponse_VERDICT_VALID,
		EvaluatedAt:      timestamppb.New(at),
		Carrier:          "oid4vp",
		TemplateId:       "age",
		TemplateVersion:  2,
		PolicySetId:      "strict",
		PolicySetVersion: 1,
		Checks: []*policyv1.CheckResult{
			{Name: "audience", Outcome: policyv1.Outcome_OUTCOME_PASS, Detail: "the audience matches"},
		},
		CrossChecks: []*policyv1.CheckResult{
			{Name: "SAME_SUBJECT", Outcome: policyv1.Outcome_OUTCOME_FAIL, Detail: "the subjects differ"},
		},
		Credentials: []*resultsv1.CredentialSummary{{
			Title: "Passport", Type: "Passport", Issuer: "did:web:issuer", IssuerName: "Ministry",
			Trust: "trusted", Role: "subject",
			DisplayFields: map[string]string{"given_name": "Ada", "family_name": "Lovelace"},
			Validity: &commonv1.ValidityWindow{
				ValidFrom: timestamppb.New(at.Add(-time.Hour)), ValidUntil: timestamppb.New(at.Add(time.Hour)),
			},
			Checks: []*policyv1.CheckResult{
				{Name: "signature", Outcome: policyv1.Outcome_OUTCOME_PASS, Detail: "the signature is valid"},
				{Name: "status", Outcome: policyv1.Outcome_OUTCOME_ERROR, Detail: "the list is not reachable"},
				{Name: "schema", Outcome: policyv1.Outcome_OUTCOME_SKIP, Detail: "no schema"},
			},
			DecodedJson: `{"vct":"Passport"}`,
		}},
	}
}

func newCards(t *testing.T) *Cards {
	t.Helper()
	c, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestResultCards(t *testing.T) {
	got, err := newCards(t).Result(sample())
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, want := range []string{"Verification summary", "Passport", "Ministry", "given_name",
		"Full credential as JSON", "SAME_SUBJECT", "valid"} {
		if !strings.Contains(body, want) {
			t.Fatalf("want %q in the cards", want)
		}
	}
	a11ytest.AssertFragment(t, body)
}

func TestResultWithoutCredentials(t *testing.T) {
	r := &resultsv1.VerificationResult{Id: "empty"}
	got, err := newCards(t).Result(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "0 credential(s)") {
		t.Fatalf("want the credential count, got %s", got)
	}
}

func TestCredentialWithoutFields(t *testing.T) {
	r := &resultsv1.VerificationResult{Credentials: []*resultsv1.CredentialSummary{{}}}
	got, err := newCards(t).Result(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Credential") || !strings.Contains(string(got), "No check ran") {
		t.Fatalf("unexpected cards: %s", got)
	}
}

func TestRawJSONFallback(t *testing.T) {
	if got := rawJSON("not json"); got != "not json" {
		t.Fatalf("want the text, got %v", got)
	}
	if _, ok := rawJSON(`{"a":1}`).(map[string]any); !ok {
		t.Fatal("want the decoded object")
	}
}

func TestWords(t *testing.T) {
	outcomes := map[policyv1.Outcome][2]string{
		policyv1.Outcome_OUTCOME_PASS:        {"pass", "ok"},
		policyv1.Outcome_OUTCOME_FAIL:        {"fail", "bad"},
		policyv1.Outcome_OUTCOME_SKIP:        {"skip", "info"},
		policyv1.Outcome_OUTCOME_ERROR:       {"error", "warn"},
		policyv1.Outcome_OUTCOME_UNSPECIFIED: {"unknown", "info"},
	}
	for in, want := range outcomes {
		if got := outcomeWord(in); got != want[0] {
			t.Fatalf("%s: want %s, got %s", in, want[0], got)
		}
		if got := outcomeStatus(in); got != want[1] {
			t.Fatalf("%s: want %s, got %s", in, want[1], got)
		}
	}
	verdicts := map[policyv1.EvaluateResponse_Verdict]string{
		policyv1.EvaluateResponse_VERDICT_VALID:         "ok",
		policyv1.EvaluateResponse_VERDICT_INVALID:       "bad",
		policyv1.EvaluateResponse_VERDICT_INDETERMINATE: "warn",
		policyv1.EvaluateResponse_VERDICT_UNSPECIFIED:   "info",
	}
	for in, want := range verdicts {
		if got := verdictStatus(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
	trust := map[string]string{
		"trusted": "ok", "untrusted": "bad", "unknown": "warn", "unavailable": "warn", "": "info",
	}
	for in, want := range trust {
		if got := trustStatus(in); got != want {
			t.Fatalf("%q: want %s, got %s", in, want, got)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := orDash(""); got != "not known" {
		t.Fatalf("want the fallback, got %q", got)
	}
	if got := versioned("", 0); got != "not known" {
		t.Fatalf("want the fallback, got %q", got)
	}
	if got := versioned("one", 0); got != "one" {
		t.Fatalf("want the id, got %q", got)
	}
	if got := versioned("one", 2); got != "one v2" {
		t.Fatalf("want the version, got %q", got)
	}
	if got := stamp(at, false); got != "not known" {
		t.Fatalf("want the fallback, got %q", got)
	}
	if got := title(&resultsv1.CredentialSummary{Type: "Passport"}); got != "Passport" {
		t.Fatalf("want the type, got %q", got)
	}
}

func TestKit(t *testing.T) {
	if newCards(t).Kit() == nil {
		t.Fatal("want the kit")
	}
}

func TestBrokenKit(t *testing.T) {
	c := &Cards{kit: &components.Kit{}}
	if _, err := c.Result(sample()); err == nil {
		t.Fatal("want an error from a kit without templates")
	}
}

// TestResultCardShowsCacheAge names where the trust material came from:
// online, or the cache with its age and a stale mark.
func TestResultCardShowsCacheAge(t *testing.T) {
	c := newCards(t)
	online, err := c.Result(sample())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(online), "Trust material") || !strings.Contains(string(online), "Read online") {
		t.Fatal("want the online trust material row")
	}
	r := sample()
	r.MaterialAge, r.MaterialStale = durationpb.New(2*time.Hour), true
	cached, err := c.Result(r)
	if err != nil {
		t.Fatal(err)
	}
	body := string(cached)
	a11ytest.AssertFragment(t, body)
	for _, want := range []string{"From the cache, 2 h old", "Stale"} {
		if !strings.Contains(body, want) {
			t.Errorf("the summary lacks %q", want)
		}
	}
}

// TestResultCardShowsStackChecks lists the checks the stack verifier
// ran beside the checks of VCA.
func TestResultCardShowsStackChecks(t *testing.T) {
	r := sample()
	r.Stack = "Modern stack"
	r.StackChecks = []*backendv1.GetResultResponse_DpgCheck{
		{Name: "signature", Passed: true}, {Name: "expired", Passed: false, Reason: "The credential expired."},
	}
	got, err := newCards(t).Result(r)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	a11ytest.AssertFragment(t, body)
	for _, want := range []string{"Checks of Modern stack", "expired", "The credential expired.", "Checked by", "Modern stack"} {
		if !strings.Contains(body, want) {
			t.Errorf("the summary lacks %q", want)
		}
	}
	if strings.Contains(string(mustResult(t, sample())), "summary-stack") {
		t.Error("a result without a stack shows stack checks")
	}
}

func mustResult(t *testing.T, r *resultsv1.VerificationResult) []byte {
	t.Helper()
	got, err := newCards(t).Result(r)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(got)
}

// TestResultCardTitleReadsAsWords is P4-05. The card of a credential
// names its type as words, for a title the summary stored and for a
// type with no title.
func TestResultCardTitleReadsAsWords(t *testing.T) {
	r := &resultsv1.VerificationResult{Credentials: []*resultsv1.CredentialSummary{
		{Title: "OpenBadgeCredential", Type: "OpenBadgeCredential"},
		{Type: "urn:eu.europa.ec.eudi:pid:1"},
	}}
	got, err := newCards(t).Result(r)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, want := range []string{">Open badge credential<", ">PID<"} {
		if !strings.Contains(body, want) {
			t.Errorf("the cards lack the title %q:\n%s", want, body)
		}
	}
	a11ytest.AssertFragment(t, body)
}
