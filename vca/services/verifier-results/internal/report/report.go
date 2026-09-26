// SPDX-License-Identifier: Apache-2.0

// Package report writes the PDF report of one verification result
// through core/pdf (spec VE6). The report holds the verdict, the facts,
// the checks of VCA and of the stack verifier, the age of the trust
// material, and one block per credential. It never holds the raw
// presentation, the decoded credential, or a claim value: a credential
// block names the disclosed claims only.
package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/pdf"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
)

// Layout of the page, in points.
const (
	margin    = 56.0
	top       = 786.0
	bottom    = 92.0
	footY     = 58.0
	bodySize  = 9.5
	headSize  = 11.5
	titleSize = 18.0
	indent    = 12.0
)

// TimeFormat is how the report prints a time.
const TimeFormat = "2006-01-02 15:04 UTC"

// writer places lines from the top of the page down and stops at the
// foot of the page.
type writer struct {
	doc  *pdf.Doc
	y    float64
	full bool
}

// line writes text, wrapped to the page width. It returns false once
// the page is full, after it wrote the note that the page cut the
// result.
func (w *writer) line(font pdf.Font, size, left float64, text string) bool {
	if w.full {
		return false
	}
	for _, part := range wrap(font, size, pdf.PageWidth-margin-left, text) {
		if w.y-size*1.5 < bottom {
			w.full = true
			w.doc.Text(pdf.HelveticaOblique, bodySize, margin, w.y-bodySize*1.5, 0.35, msg.T("verifier.report.cut"))
			return false
		}
		w.y -= size * 1.45
		w.doc.Text(font, size, left, w.y, 0.12, part)
	}
	return true
}

// gap leaves space before a heading.
func (w *writer) gap() { w.y -= 8 }

// wrap splits text into lines no wider than width.
func wrap(font pdf.Font, size, width float64, text string) []string {
	var out []string
	cur := ""
	for _, word := range strings.Fields(text) {
		next := word
		if cur != "" {
			next = cur + " " + word
		}
		if cur != "" && pdf.TextWidth(font, size, next) > width {
			out = append(out, cur)
			next = word
		}
		cur = next
	}
	if cur != "" || len(out) == 0 {
		out = append(out, cur)
	}
	return out
}

// PDF writes the report of r. query is the display name of the saved
// query, or empty. now is the time of writing.
func PDF(r *resultsv1.VerificationResult, query string, now time.Time) []byte {
	title := msg.T("verifier.report.title.label")
	w := &writer{doc: pdf.New(title), y: top}
	w.line(pdf.HelveticaBold, titleSize, margin, title)
	w.line(pdf.Helvetica, bodySize, margin, msg.T("verifier.report.lead", now.UTC().Format(TimeFormat)))
	w.doc.Line(margin, w.y-8, pdf.PageWidth-margin, w.y-8, 0.6, 0.75)
	w.gap()
	for _, f := range facts(r, query) {
		w.line(pdf.Helvetica, bodySize, margin, f)
	}
	checks(w, msg.T("verifier.report.checks.label"), append(append([]*policyv1.CheckResult{}, r.GetChecks()...), r.GetCrossChecks()...))
	if len(r.GetStackChecks()) > 0 {
		w.gap()
		w.line(pdf.HelveticaBold, headSize, margin, msg.T("verifier.card.stack.caption.label", r.GetStack()))
		for _, c := range r.GetStackChecks() {
			word := msg.T("verifier.report.pass.label")
			if !c.GetPassed() {
				word = msg.T("verifier.report.fail.label")
			}
			w.line(pdf.Helvetica, bodySize, margin+indent, joinCheck(c.GetName(), word, c.GetReason()))
		}
	}
	for _, c := range r.GetCredentials() {
		credential(w, c)
	}
	w.doc.Line(margin, footY+16, pdf.PageWidth-margin, footY+16, 0.4, 0.8)
	w.doc.Text(pdf.Helvetica, 8, margin, footY, 0.4, msg.T("verifier.report.privacy"))
	return w.doc.Bytes()
}

// facts returns the lines of the facts of the result.
func facts(r *resultsv1.VerificationResult, query string) []string {
	at := msg.T("common.unknown.label")
	if r.GetEvaluatedAt() != nil {
		at = r.GetEvaluatedAt().AsTime().UTC().Format(TimeFormat)
	}
	q := versioned(r.GetTemplateId(), r.GetTemplateVersion())
	if query != "" {
		q = query + " (" + q + ")"
	}
	by := r.GetStack()
	if by == "" {
		by = msg.T("verifier.card.vca.label")
	}
	material := msg.T("verifier.card.material.online.label")
	if r.GetMaterialAge() != nil {
		material = msg.T("verifier.card.material.cache", msg.Age(r.GetMaterialAge().AsDuration()))
		if r.GetMaterialStale() {
			material += " " + msg.T("verifier.card.stale.label") + "."
		}
	}
	return []string{
		msg.T("verifier.report.fact.label", msg.T("verifier.report.result.label"), r.GetId()),
		msg.T("verifier.report.fact.label", msg.T("verifier.results.verdict.label"), verdictWord(r.GetVerdict())),
		msg.T("verifier.report.fact.label", msg.T("verifier.results.column.at.label"), at),
		msg.T("verifier.report.fact.label", msg.T("verifier.results.query.label"), q),
		msg.T("verifier.report.fact.label", msg.T("verifier.report.policy.label"), versioned(r.GetPolicySetId(), r.GetPolicySetVersion())),
		msg.T("verifier.report.fact.label", msg.T("verifier.card.checked_by.label"), by),
		msg.T("verifier.report.fact.label", msg.T("verifier.card.material.label"), material),
	}
}

// checks writes a heading and one line per check.
func checks(w *writer, heading string, list []*policyv1.CheckResult) {
	if len(list) == 0 {
		return
	}
	w.gap()
	w.line(pdf.HelveticaBold, headSize, margin, heading)
	for _, c := range list {
		if !w.line(pdf.Helvetica, bodySize, margin+indent, joinCheck(c.GetName(), outcomeWord(c.GetOutcome()), c.GetDetail())) {
			return
		}
	}
}

// credential writes the block of one credential without claim values.
func credential(w *writer, c *resultsv1.CredentialSummary) {
	w.gap()
	title := vc.TypeTitle(c.GetTitle())
	if title == "" {
		title = vc.TypeTitle(c.GetType())
	}
	w.line(pdf.HelveticaBold, headSize, margin, title)
	issuer := c.GetIssuer()
	if n := c.GetIssuerName(); n != "" {
		issuer = n + " (" + c.GetIssuer() + ")"
	}
	w.line(pdf.Helvetica, bodySize, margin+indent, msg.T("verifier.report.fact.label", msg.T("verifier.results.issuer.label"), issuer))
	w.line(pdf.Helvetica, bodySize, margin+indent, msg.T("verifier.report.fact.label", msg.T("verifier.report.trust.label"), c.GetTrust()))
	if u := c.GetValidity().GetValidUntil(); u != nil {
		w.line(pdf.Helvetica, bodySize, margin+indent, msg.T("verifier.report.fact.label", msg.T("verifier.report.until.label"), u.AsTime().UTC().Format(TimeFormat)))
	}
	if len(c.GetDisplayFields()) > 0 {
		names := make([]string, 0, len(c.GetDisplayFields()))
		for k := range c.GetDisplayFields() {
			names = append(names, k)
		}
		sort.Strings(names)
		w.line(pdf.Helvetica, bodySize, margin+indent, msg.T("verifier.report.fact.label", msg.T("verifier.report.claims.label"), strings.Join(names, ", ")))
	}
	for _, check := range c.GetChecks() {
		if !w.line(pdf.Helvetica, bodySize, margin+indent, joinCheck(check.GetName(), outcomeWord(check.GetOutcome()), check.GetDetail())) {
			return
		}
	}
}

// joinCheck writes one check as "name, outcome: detail".
func joinCheck(name, outcome, detail string) string {
	out := name + ", " + outcome
	if detail != "" {
		out += ": " + detail
	}
	return out
}

// versioned joins an id and a version.
func versioned(id string, version int32) string {
	if id == "" {
		return msg.T("common.unknown.label")
	}
	if version == 0 {
		return id
	}
	return id + " v" + strconv.Itoa(int(version))
}

// verdictWord names a verdict.
func verdictWord(v policyv1.EvaluateResponse_Verdict) string {
	switch v {
	case policyv1.EvaluateResponse_VERDICT_VALID:
		return msg.T("verifier.verdict.valid.label")
	case policyv1.EvaluateResponse_VERDICT_INVALID:
		return msg.T("verifier.verdict.invalid.label")
	case policyv1.EvaluateResponse_VERDICT_INDETERMINATE:
		return msg.T("verifier.verdict.indeterminate.label")
	case policyv1.EvaluateResponse_VERDICT_UNSPECIFIED:
	}
	return msg.T("common.unknown.label")
}

// outcomeWord names the outcome of a check.
func outcomeWord(o policyv1.Outcome) string {
	switch o {
	case policyv1.Outcome_OUTCOME_PASS:
		return msg.T("verifier.report.pass.label")
	case policyv1.Outcome_OUTCOME_FAIL:
		return msg.T("verifier.report.fail.label")
	case policyv1.Outcome_OUTCOME_SKIP:
		return msg.T("verifier.report.skip.label")
	case policyv1.Outcome_OUTCOME_ERROR:
		return msg.T("verifier.report.error.label")
	case policyv1.Outcome_OUTCOME_UNSPECIFIED:
	}
	return msg.T("common.unknown.label")
}
