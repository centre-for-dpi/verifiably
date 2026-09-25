// SPDX-License-Identifier: Apache-2.0

// Package cards renders one verification result as the card list of
// ADR-025 decision 2: a summary card and one card per credential. Each
// credential card shows the issuer name, a trust badge, the subject
// display fields, the verdict, and the check list. A disclosure holds
// the full JSON (ADR-025 decisions 2 and 6).
//
// The staff portal and the public citizen page both render this list,
// so they cannot drift apart.
package cards

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"time"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/export"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Cards renders result cards with the UI kit.
type Cards struct {
	kit *components.Kit
}

// New builds the renderer. A nil kit builds a new one.
func New(kit *components.Kit) (*Cards, error) {
	if kit == nil {
		k, err := components.New()
		if err != nil {
			return nil, err
		}
		kit = k
	}
	return &Cards{kit: kit}, nil
}

// Kit returns the UI kit the renderer uses.
func (c *Cards) Kit() *components.Kit { return c.kit }

// draft collects rendered components and keeps the first error, so one
// check at the end reports every render problem.
type draft struct {
	kit   *components.Kit
	parts []template.HTML
	err   error
}

// html renders one component and keeps the first error.
func (d *draft) html(name string, data any) template.HTML {
	if d.err != nil {
		return ""
	}
	out, err := d.kit.HTML(name, data)
	if err != nil {
		d.err = err
	}
	return out
}

// add renders one component and appends it.
func (d *draft) add(name string, data any) {
	d.parts = append(d.parts, d.html(name, data))
}

// body returns the appended components as one fragment.
func (d *draft) body() template.HTML { return components.Join(d.parts...) }

// Result returns the card list of one result.
func (c *Cards) Result(r *resultsv1.VerificationResult) (template.HTML, error) {
	d := &draft{kit: c.kit}
	d.parts = append(d.parts, c.summary(d, r))
	for i, cred := range r.GetCredentials() {
		d.parts = append(d.parts, c.credential(d, i, cred))
	}
	if d.err != nil {
		return "", d.err
	}
	return d.body(), nil
}

// summary returns the card of the whole presentation.
func (c *Cards) summary(d *draft, r *resultsv1.VerificationResult) template.HTML {
	verdict := d.html("badge", components.Badge{
		Status: verdictStatus(r.GetVerdict()), Text: export.VerdictWord(r.GetVerdict()),
	})
	inner := &draft{kit: c.kit}
	inner.add("table", components.Table{
		ID: "summary-facts", Caption: "Facts of the verification",
		Columns: []string{"Name", "Value"},
		Rows: []components.Row{
			{{Text: "Verdict"}, {HTML: verdict}},
			{{Text: "Checked at"}, {Text: stamp(r.GetEvaluatedAt().AsTime(), r.GetEvaluatedAt() != nil)}},
			{{Text: "Carrier"}, {Text: orDash(r.GetCarrier())}},
			{{Text: "Template"}, {Text: versioned(r.GetTemplateId(), r.GetTemplateVersion())}},
			{{Text: "Policy set"}, {Text: versioned(r.GetPolicySetId(), r.GetPolicySetVersion())}},
		},
	})
	checks := append(append([]*policyv1.CheckResult{}, r.GetChecks()...), r.GetCrossChecks()...)
	if len(checks) > 0 {
		inner.parts = append(inner.parts, c.checks(inner, "summary-checks", "Checks of the presentation", checks))
	}
	keepError(d, inner)
	return d.html("card", components.Card{
		ID:    "summary",
		Title: "Verification summary",
		Text:  fmt.Sprintf("%d credential(s) in this presentation.", len(r.GetCredentials())),
		Body:  inner.body(),
	})
}

// credential returns the card of one credential.
func (c *Cards) credential(d *draft, index int, cred *resultsv1.CredentialSummary) template.HTML {
	id := "cred-" + strconv.Itoa(index)
	trust := d.html("badge", components.Badge{
		Status: trustStatus(cred.GetTrust()), Text: "issuer " + orDash(cred.GetTrust()),
	})
	rows := []components.Row{
		{{Text: "Issuer"}, {Text: orDash(cred.GetIssuerName())}},
		{{Text: "Issuer id"}, {Text: orDash(cred.GetIssuer())}},
		{{Text: "Trust"}, {HTML: trust}},
		{{Text: "Type"}, {Text: orDash(cred.GetType())}},
	}
	if role := cred.GetRole(); role != "" {
		rows = append(rows, components.Row{{Text: "Role"}, {Text: role}})
	}
	if v := cred.GetValidity(); v != nil {
		rows = append(rows,
			components.Row{{Text: "Valid from"}, {Text: stamp(v.GetValidFrom().AsTime(), v.GetValidFrom() != nil)}},
			components.Row{{Text: "Valid until"}, {Text: stamp(v.GetValidUntil().AsTime(), v.GetValidUntil() != nil)}},
		)
	}
	for _, name := range export.SortedKeys(cred.GetDisplayFields()) {
		rows = append(rows, components.Row{{Text: name}, {Text: cred.GetDisplayFields()[name]}})
	}
	inner := &draft{kit: c.kit}
	inner.add("table", components.Table{
		ID: id + "-facts", Caption: "Credential and subject fields",
		Columns: []string{"Name", "Value"}, Rows: rows,
	})
	inner.parts = append(inner.parts, c.checks(inner, id+"-checks", "Checks of this credential", cred.GetChecks()))
	if cred.GetDecodedJson() != "" {
		inner.add("json", components.JSON{
			ID: id + "-json", Summary: "Full credential as JSON", Data: rawJSON(cred.GetDecodedJson()),
		})
	}
	keepError(d, inner)
	return d.html("card", components.Card{
		ID:    id,
		Title: title(cred),
		Text:  orDash(cred.GetIssuerName()),
		Body:  inner.body(),
	})
}

// checks returns the table of a check list.
func (c *Cards) checks(d *draft, id, caption string, list []*policyv1.CheckResult) template.HTML {
	table := components.Table{
		ID: id, Caption: caption, Columns: []string{"Check", "Outcome", "Detail"},
		Empty: "No check ran",
	}
	for _, check := range list {
		table.Rows = append(table.Rows, components.Row{
			{Text: check.GetName()},
			{HTML: d.html("badge", components.Badge{
				Status: outcomeStatus(check.GetOutcome()), Text: outcomeWord(check.GetOutcome()),
			})},
			{Text: check.GetDetail()},
		})
	}
	return d.html("table", table)
}

// keepError copies the first error of inner into d.
func keepError(d, inner *draft) {
	if d.err == nil {
		d.err = inner.err
	}
}

// title returns the card title of a credential.
func title(cred *resultsv1.CredentialSummary) string {
	if t := cred.GetTitle(); t != "" {
		return t
	}
	if t := cred.GetType(); t != "" {
		return t
	}
	return "Credential"
}

// rawJSON returns the decoded JSON, or the text when it does not parse.
func rawJSON(text string) any {
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return text
	}
	return v
}

// outcomeWord returns the plain word of an outcome.
func outcomeWord(o policyv1.Outcome) string {
	switch o {
	case policyv1.Outcome_OUTCOME_PASS:
		return "pass"
	case policyv1.Outcome_OUTCOME_FAIL:
		return "fail"
	case policyv1.Outcome_OUTCOME_SKIP:
		return "skip"
	case policyv1.Outcome_OUTCOME_ERROR:
		return "error"
	case policyv1.Outcome_OUTCOME_UNSPECIFIED:
	}
	return "unknown"
}

// outcomeStatus maps an outcome to a badge status.
func outcomeStatus(o policyv1.Outcome) string {
	switch o {
	case policyv1.Outcome_OUTCOME_PASS:
		return "ok"
	case policyv1.Outcome_OUTCOME_FAIL:
		return "bad"
	case policyv1.Outcome_OUTCOME_ERROR:
		return "warn"
	case policyv1.Outcome_OUTCOME_SKIP, policyv1.Outcome_OUTCOME_UNSPECIFIED:
	}
	return "info"
}

// verdictStatus maps a verdict to a badge status.
func verdictStatus(v policyv1.EvaluateResponse_Verdict) string {
	switch v {
	case policyv1.EvaluateResponse_VERDICT_VALID:
		return "ok"
	case policyv1.EvaluateResponse_VERDICT_INVALID:
		return "bad"
	case policyv1.EvaluateResponse_VERDICT_INDETERMINATE:
		return "warn"
	case policyv1.EvaluateResponse_VERDICT_UNSPECIFIED:
	}
	return "info"
}

// trustStatus maps a trust word to a badge status.
func trustStatus(word string) string {
	switch word {
	case "trusted":
		return "ok"
	case "untrusted":
		return "bad"
	case "unknown", "unavailable":
		return "warn"
	}
	return "info"
}

// orDash returns the value, or a dash when it is empty.
func orDash(value string) string {
	if value == "" {
		return "not known"
	}
	return value
}

// versioned joins an id and a version.
func versioned(id string, version int32) string {
	if id == "" {
		return "not known"
	}
	if version == 0 {
		return id
	}
	return id + " v" + strconv.Itoa(int(version))
}

// stamp formats a time, or reports that it is absent.
func stamp(t time.Time, present bool) string {
	if !present {
		return "not known"
	}
	return t.UTC().Format(time.RFC3339)
}

// Age names a duration in its largest whole unit: minutes under an
// hour, hours under two days, then days. A negative age reads as zero.
func Age(d time.Duration) string {
	switch {
	case d < time.Hour:
		return msg.T("verifier.age.minutes.label", strconv.Itoa(int(max(d, 0)/time.Minute)))
	case d < 48*time.Hour:
		return msg.T("verifier.age.hours.label", strconv.Itoa(int(d/time.Hour)))
	}
	return msg.T("verifier.age.days.label", strconv.Itoa(int(d/(24*time.Hour))))
}
