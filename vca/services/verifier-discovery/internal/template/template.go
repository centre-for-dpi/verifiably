// SPDX-License-Identifier: Apache-2.0

// Package template holds the presentation template record and its pure
// rules (ADR-022 decisions 3 and 4). A template stores the request as a
// DCQL query. The package also generates a Presentation Exchange 2.0
// definition for a Digital Public Good that needs the older language.
package template

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
)

// MaxNameLength caps the display name and the purpose.
const MaxNameLength = 200

// MaxIDLength caps a template id.
const MaxIDLength = 64

// Template is one stored version of a presentation request.
type Template struct {
	// ID is stable across versions.
	ID string `json:"id"`
	// Version starts at 1 and increases by 1.
	Version int32 `json:"version"`
	// DisplayName is the name the pages show.
	DisplayName string `json:"display_name"`
	// DCQL is the query as a JSON string. It is the request the wallet
	// gets.
	DCQL string `json:"dcql"`
	// Queries is the structured view of the same request.
	Queries []Query `json:"queries,omitempty"`
	// Purpose is the reason the citizen sees.
	Purpose string `json:"purpose,omitempty"`
	// TenantID is the tenant that owns the template.
	TenantID string `json:"tenant_id,omitempty"`
	// CreatedBy is the staff subject that created this version.
	CreatedBy string `json:"created_by,omitempty"`
	// CreatedAt is the creation time of this version.
	CreatedAt time.Time `json:"created_at"`
	// Kind is the query language: KindDCQL, KindPE, or KindNative
	// (ADR-042 decision 1). Build sets KindDCQL when it is empty.
	Kind string `json:"kind,omitempty"`
	// Predicates are the claim rules that DCQL cannot hold. The policy
	// service enforces them (ADR-042 decision 3).
	Predicates []Predicate `json:"predicates,omitempty"`
	// RequireTrustedIssuer asks that the issuer sits on a trust list.
	RequireTrustedIssuer bool `json:"require_trusted_issuer,omitempty"`
	// RequireStatus asks that the credential passes its status check.
	RequireStatus bool `json:"require_status,omitempty"`
	// PolicySetID is the policy set that holds the rules. The service
	// sets it when the template has a rule.
	PolicySetID string `json:"policy_set_id,omitempty"`
}

// The kinds of a template.
const (
	KindDCQL   = "dcql"
	KindPE     = "pe"
	KindNative = "native"
)

// The operators of a claim rule. They are the operators of the
// claim_predicate check of core/policy.
const (
	OpBefore       = policy.OpBefore
	OpAfter        = policy.OpAfter
	OpAtLeastYears = policy.OpAtLeastYears
	OpAtMostYears  = policy.OpAtMostYears
)

// Predicate is one claim rule of a template.
type Predicate struct {
	// QueryID is the credential query the rule applies to.
	QueryID string `json:"query_id"`
	// Path is the dotted claim path.
	Path string `json:"path"`
	// Op is one of the Op constants.
	Op string `json:"op"`
	// Value is a date such as 2008-01-31, or a whole number of years.
	Value string `json:"value"`
}

// ClaimValues limits the accepted values of one claim.
type ClaimValues struct {
	// Path is the dotted claim path.
	Path string `json:"path"`
	// Values are the accepted values, as text.
	Values []string `json:"values"`
}

// Query is one credential the template asks for.
type Query struct {
	// QueryID is the DCQL credential query id.
	QueryID string `json:"query_id"`
	// Type is the credential type.
	Type string `json:"type"`
	// Format is the wire format identifier. Empty accepts every format.
	Format string `json:"format,omitempty"`
	// Claims holds the dotted claim paths.
	Claims []string `json:"claims,omitempty"`
	// Issuers holds the issuer URLs to accept. Empty accepts every
	// trusted issuer.
	Issuers []string `json:"issuers,omitempty"`
	// Values limits the accepted values of some claims.
	Values []ClaimValues `json:"values,omitempty"`
	// ClaimSets lists the acceptable combinations of claim paths.
	ClaimSets [][]string `json:"claim_sets,omitempty"`
}

// ValidID reports whether the id is a safe store key segment.
func ValidID(id string) bool {
	if id == "" || len(id) > MaxIDLength {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return id != "." && id != ".."
}

// IDFrom turns a display name into a template id.
func IDFrom(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == ' ':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	for strings.Contains(id, "--") {
		id = strings.ReplaceAll(id, "--", "-")
	}
	if len(id) > MaxIDLength {
		id = id[:MaxIDLength]
	}
	return id
}

// Build fills the DCQL of a template from its queries, or reads the DCQL
// the caller sent. It validates the result and the rules.
func Build(t Template) (Template, error) {
	if strings.TrimSpace(t.DisplayName) == "" {
		return Template{}, errors.New("template: the display name is required")
	}
	if len(t.DisplayName) > MaxNameLength {
		return Template{}, fmt.Errorf("template: the display name is longer than %d characters", MaxNameLength)
	}
	if len(t.Purpose) > MaxNameLength {
		return Template{}, fmt.Errorf("template: the purpose is longer than %d characters", MaxNameLength)
	}
	switch t.Kind {
	case "":
		t.Kind = KindDCQL
	case KindDCQL:
	default:
		return Template{}, fmt.Errorf("template: the service stores DCQL templates, not %q", t.Kind)
	}
	q, err := queryOf(t)
	if err != nil {
		return Template{}, err
	}
	data, err := dcql.Marshal(q)
	if err != nil {
		return Template{}, err
	}
	t.DCQL = string(data)
	t.Queries = QueriesOf(q)
	if err := checkPredicates(t); err != nil {
		return Template{}, err
	}
	return t, nil
}

// queryOf reads the DCQL of a template, or builds it from the queries.
func queryOf(t Template) (dcql.Query, error) {
	if strings.TrimSpace(t.DCQL) != "" {
		return dcql.Parse([]byte(t.DCQL))
	}
	if len(t.Queries) == 0 {
		return dcql.Query{}, errors.New("template: the template asks for no credential")
	}
	selections := make([]dcql.Selection, 0, len(t.Queries))
	for _, q := range t.Queries {
		sel := dcql.Selection{
			ID: q.QueryID, Format: formatOrDefault(q.Format), Type: q.Type, Claims: q.Claims, Issuers: q.Issuers, ClaimSets: q.ClaimSets,
		}
		for _, v := range q.Values {
			if sel.Values == nil {
				sel.Values = map[string][]any{}
			}
			for _, text := range v.Values {
				sel.Values[v.Path] = append(sel.Values[v.Path], text)
			}
		}
		selections = append(selections, sel)
	}
	return dcql.Build(selections, t.Purpose)
}

// checkPredicates checks every rule against the queries: the query
// exists, it asks for the claim, and the operator and the value parse.
func checkPredicates(t Template) error {
	for _, p := range t.Predicates {
		var query *Query
		for i := range t.Queries {
			if t.Queries[i].QueryID == p.QueryID {
				query = &t.Queries[i]
			}
		}
		if query == nil {
			return fmt.Errorf("template: the rule names the unknown query %q", p.QueryID)
		}
		if !slices.Contains(query.Claims, p.Path) {
			return fmt.Errorf("template: the rule names the claim %q, which the query %q does not ask for", p.Path, p.QueryID)
		}
		switch p.Op {
		case OpBefore, OpAfter:
			if _, err := time.Parse(time.DateOnly, p.Value); err != nil {
				return fmt.Errorf("template: the rule on %q needs a date such as 2008-01-31", p.Path)
			}
		case OpAtLeastYears, OpAtMostYears:
			if n, err := strconv.Atoi(p.Value); err != nil || n < 0 {
				return fmt.Errorf("template: the rule on %q needs a whole number of years", p.Path)
			}
		default:
			return fmt.Errorf("template: the rule on %q has the unknown operator %q", p.Path, p.Op)
		}
	}
	return nil
}

// HasRules reports whether the template needs a policy set of its own.
func (t Template) HasRules() bool {
	return t.RequireTrustedIssuer || t.RequireStatus || len(t.Predicates) > 0
}

// PolicyChecks returns the checks of the policy set of the template:
// the trust chain, the status check, and one claim_predicate check for
// each rule, every one blocking (ADR-042 decision 3).
func (t Template) PolicyChecks() []*policyv1.PolicySet_Check {
	var out []*policyv1.PolicySet_Check
	if t.RequireTrustedIssuer {
		out = append(out, &policyv1.PolicySet_Check{Name: policy.NameTrustChain, Blocking: true})
	}
	if t.RequireStatus {
		out = append(out, &policyv1.PolicySet_Check{Name: policy.NameStatus, Blocking: true, Params: map[string]string{"fail_mode": "closed"}})
	}
	types := map[string]string{}
	for _, q := range t.Queries {
		types[q.QueryID] = q.Type
	}
	for _, p := range t.Predicates {
		params := map[string]string{"path": p.Path, "op": p.Op, "value": p.Value}
		if typ := types[p.QueryID]; typ != "" {
			params["type"] = typ
		}
		out = append(out, &policyv1.PolicySet_Check{Name: policy.NameClaimPredicate, Blocking: true, Params: params})
	}
	return out
}

// formatOrDefault returns the format, or the SD-JWT VC format when the
// caller named none.
func formatOrDefault(format string) string {
	if format == "" {
		return dcql.FormatSDJWT
	}
	return format
}

// QueriesOf returns the structured view of a DCQL query.
func QueriesOf(q dcql.Query) []Query {
	out := make([]Query, 0, len(q.Credentials))
	for _, c := range q.Credentials {
		item := Query{QueryID: c.ID, Type: c.Type(), Format: c.Format, Claims: c.ClaimPaths()}
		for _, a := range c.TrustedAuthorities {
			item.Issuers = append(item.Issuers, a.Values...)
		}
		paths := map[string]string{}
		for _, cl := range c.Claims {
			paths[cl.ID] = cl.Path.String()
			if len(cl.Values) > 0 {
				item.Values = append(item.Values, ClaimValues{Path: cl.Path.String(), Values: cl.ValueStrings()})
			}
		}
		for _, set := range c.ClaimSets {
			var claims []string
			for _, id := range set {
				claims = append(claims, paths[id])
			}
			item.ClaimSets = append(item.ClaimSets, claims)
		}
		out = append(out, item)
	}
	return out
}

// PresentationExchange generates the Presentation Exchange 2.0
// definition of a template.
func (t Template) PresentationExchange() ([]byte, error) {
	q, err := dcql.Parse([]byte(t.DCQL))
	if err != nil {
		return nil, err
	}
	id := t.ID
	if id == "" {
		id = "presentation-request"
	}
	return dcql.MarshalPresentationExchange(q, id, t.Purpose)
}

// Query returns the parsed DCQL query of a template.
func (t Template) Query() (dcql.Query, error) {
	return dcql.Parse([]byte(t.DCQL))
}

// FromProto reads a template message. It ignores the version and the
// timestamps, which the service assigns.
func FromProto(m *discoveryv1.PresentationTemplate) Template {
	t := Template{
		ID:          m.GetId(),
		DisplayName: m.GetDisplayName(),
		DCQL:        m.GetDcql(),
		Purpose:     m.GetPurpose(),
		TenantID:    m.GetTenantId(),
		CreatedBy:   m.GetCreatedBy(),
		Kind:        kindName(m.GetKind()),

		RequireTrustedIssuer: m.GetRequireTrustedIssuer(),
		RequireStatus:        m.GetRequireStatus(),
		PolicySetID:          m.GetPolicySetId(),
	}
	for _, q := range m.GetQueries() {
		item := Query{
			QueryID: q.GetQueryId(), Type: q.GetType(), Format: formatName(q.GetFormat()),
			Claims: q.GetClaims(), Issuers: q.GetIssuers(),
		}
		for _, v := range q.GetValues() {
			item.Values = append(item.Values, ClaimValues{Path: v.GetPath(), Values: v.GetValues()})
		}
		for _, set := range q.GetClaimSets() {
			item.ClaimSets = append(item.ClaimSets, set.GetClaims())
		}
		t.Queries = append(t.Queries, item)
	}
	for _, p := range m.GetPredicates() {
		t.Predicates = append(t.Predicates, Predicate{QueryID: p.GetQueryId(), Path: p.GetPath(), Op: opName(p.GetOp()), Value: p.GetValue()})
	}
	return t
}

// ToProto turns a template record into its proto message.
func (t Template) ToProto() *discoveryv1.PresentationTemplate {
	out := &discoveryv1.PresentationTemplate{
		Id: t.ID, Version: t.Version, DisplayName: t.DisplayName, Dcql: t.DCQL,
		Purpose: t.Purpose, TenantId: t.TenantID, CreatedBy: t.CreatedBy, Kind: kindOf(t.Kind),
		RequireTrustedIssuer: t.RequireTrustedIssuer, RequireStatus: t.RequireStatus, PolicySetId: t.PolicySetID,
	}
	for _, p := range t.Predicates {
		out.Predicates = append(out.Predicates, &discoveryv1.PresentationTemplate_ClaimPredicate{
			QueryId: p.QueryID, Path: p.Path, Op: opOf(p.Op), Value: p.Value,
		})
	}
	if !t.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(t.CreatedAt)
	}
	for _, q := range t.Queries {
		item := &discoveryv1.PresentationTemplate_CredentialQuery{
			QueryId: q.QueryID, Type: q.Type, Format: formatOf(q.Format), Claims: q.Claims, Issuers: q.Issuers,
		}
		for _, v := range q.Values {
			item.Values = append(item.Values, &discoveryv1.PresentationTemplate_ClaimValues{Path: v.Path, Values: v.Values})
		}
		for _, set := range q.ClaimSets {
			item.ClaimSets = append(item.ClaimSets, &discoveryv1.PresentationTemplate_ClaimSet{Claims: set})
		}
		out.Queries = append(out.Queries, item)
	}
	return out
}

// kindOf returns the proto kind of a kind name.
func kindOf(name string) discoveryv1.TemplateKind {
	switch name {
	case KindDCQL:
		return discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL
	case KindPE:
		return discoveryv1.TemplateKind_TEMPLATE_KIND_PE
	case KindNative:
		return discoveryv1.TemplateKind_TEMPLATE_KIND_NATIVE
	}
	return discoveryv1.TemplateKind_TEMPLATE_KIND_UNSPECIFIED
}

// kindName returns the kind name of a proto kind.
func kindName(k discoveryv1.TemplateKind) string {
	switch k {
	case discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL:
		return KindDCQL
	case discoveryv1.TemplateKind_TEMPLATE_KIND_PE:
		return KindPE
	case discoveryv1.TemplateKind_TEMPLATE_KIND_NATIVE:
		return KindNative
	case discoveryv1.TemplateKind_TEMPLATE_KIND_UNSPECIFIED:
	}
	return ""
}

// opOf returns the proto operator of an operator name.
func opOf(name string) discoveryv1.PresentationTemplate_ClaimPredicate_Op {
	switch name {
	case OpBefore:
		return discoveryv1.PresentationTemplate_ClaimPredicate_OP_DATE_BEFORE
	case OpAfter:
		return discoveryv1.PresentationTemplate_ClaimPredicate_OP_DATE_AFTER
	case OpAtLeastYears:
		return discoveryv1.PresentationTemplate_ClaimPredicate_OP_AT_LEAST_YEARS
	case OpAtMostYears:
		return discoveryv1.PresentationTemplate_ClaimPredicate_OP_AT_MOST_YEARS
	}
	return discoveryv1.PresentationTemplate_ClaimPredicate_OP_UNSPECIFIED
}

// opName returns the operator name of a proto operator.
func opName(op discoveryv1.PresentationTemplate_ClaimPredicate_Op) string {
	switch op {
	case discoveryv1.PresentationTemplate_ClaimPredicate_OP_DATE_BEFORE:
		return OpBefore
	case discoveryv1.PresentationTemplate_ClaimPredicate_OP_DATE_AFTER:
		return OpAfter
	case discoveryv1.PresentationTemplate_ClaimPredicate_OP_AT_LEAST_YEARS:
		return OpAtLeastYears
	case discoveryv1.PresentationTemplate_ClaimPredicate_OP_AT_MOST_YEARS:
		return OpAtMostYears
	case discoveryv1.PresentationTemplate_ClaimPredicate_OP_UNSPECIFIED:
	}
	return ""
}

// formatOf returns the proto format of a format identifier.
func formatOf(name string) commonv1.Format {
	switch name {
	case "vc+sd-jwt":
		return commonv1.Format_FORMAT_VC_SD_JWT
	case "dc+sd-jwt":
		return commonv1.Format_FORMAT_DC_SD_JWT
	case "jwt_vc_json":
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case "ldp_vc":
		return commonv1.Format_FORMAT_LDP_VC
	case "mso_mdoc":
		return commonv1.Format_FORMAT_MSO_MDOC
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// formatName returns the format identifier of a proto format.
func formatName(f commonv1.Format) string {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return "vc+sd-jwt"
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return "dc+sd-jwt"
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return "jwt_vc_json"
	case commonv1.Format_FORMAT_LDP_VC:
		return "ldp_vc"
	case commonv1.Format_FORMAT_MSO_MDOC:
		return "mso_mdoc"
	}
	return ""
}
