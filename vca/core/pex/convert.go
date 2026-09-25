// SPDX-License-Identifier: Apache-2.0

package pex

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/dcql"
)

// Loss is one part of a query that the other language cannot hold.
type Loss struct {
	// Code is one of the Loss constants.
	Code string
	// Where names the part: a credential query id or a credential set of
	// a DCQL query, or a JSON Pointer into a definition.
	Where string
	// Detail is the value the conversion kept or dropped, when it helps.
	Detail string
}

// The codes of a loss from DCQL to Presentation Exchange.
const (
	// LossIssuers: PE has no list of trusted authorities.
	LossIssuers = "issuers"
	// LossMultiple: PE cannot ask for more than one credential of a query.
	LossMultiple = "multiple"
	// LossHolderBinding: PE cannot waive the holder binding.
	LossHolderBinding = "holder_binding"
	// LossClaimSets: PE keeps the first claim set and marks the other
	// claims optional.
	LossClaimSets = "claim_sets"
	// LossOptionalSet: PE has no optional credential set.
	LossOptionalSet = "optional_set"
	// LossSetOptions: PE picks one credential of the union of the options.
	LossSetOptions = "set_options"
	// LossTypeValues: PE keeps the last type of each type list.
	LossTypeValues = "type_values"
	// LossMdocPath: a mobile document claim needs a namespace and a name.
	LossMdocPath = "mdoc_path"
)

// The codes of a loss from Presentation Exchange to DCQL.
const (
	// LossFormat: DCQL keeps one format of the descriptor.
	LossFormat = "format"
	// LossFormatLimits: DCQL has no algorithm or proof type limit.
	LossFormatLimits = "format_limits"
	// LossFrame: DCQL has no JSON-LD frame.
	LossFrame = "frame"
	// LossText: DCQL has no name or purpose for a descriptor, a field, or
	// a requirement name.
	LossText = "text"
	// LossStatuses: DCQL has no status directive.
	LossStatuses = "statuses"
	// LossHolderRules: DCQL has no subject_is_issuer, is_holder, or
	// same_subject rule.
	LossHolderRules = "holder_rules"
	// LossLimitDisclosure: DCQL cannot limit disclosure for a format
	// without selective disclosure.
	LossLimitDisclosure = "limit_disclosure"
	// LossPath: DCQL cannot hold the path, so the claim is gone.
	LossPath = "path"
	// LossAltPaths: DCQL keeps one path of a field.
	LossAltPaths = "alt_paths"
	// LossFilter: DCQL keeps only accepted values of a claim.
	LossFilter = "filter"
	// LossPredicate: DCQL cannot ask for a yes or no answer.
	LossPredicate = "predicate"
	// LossRetain: DCQL has no intent to retain.
	LossRetain = "retain"
	// LossDuplicate: a second field asks for the same claim.
	LossDuplicate = "duplicate"
	// LossAllOptional: every claim is optional, and DCQL asks for all.
	LossAllOptional = "all_optional"
	// LossNested: DCQL has no nested requirement, so each inner one is a
	// required set.
	LossNested = "nested"
	// LossPick: DCQL cannot list the combinations of the pick rule.
	LossPick = "pick"
	// LossTypeFilter: DCQL reads the type only from const, enum, or
	// contains.
	LossTypeFilter = "type_filter"
)

// MaxOptions caps the options of one credential set that a pick rule
// becomes.
const MaxOptions = 32

// Report lists what a conversion lost.
type Report struct {
	// Losses holds one entry per lost part, in the order of the source.
	Losses []Loss
}

// Lossless reports whether the conversion kept every part.
func (r Report) Lossless() bool { return len(r.Losses) == 0 }

// add keeps one loss.
func (r *Report) add(code, where, detail string) {
	r.Losses = append(r.Losses, Loss{Code: code, Where: where, Detail: detail})
}

// FromDCQL converts a DCQL query into a definition. id names the
// definition, name and purpose describe it. The report names every part
// of the query that the definition cannot hold.
func FromDCQL(q dcql.Query, id, name, purpose string) (Definition, Report, error) {
	pd, err := dcql.ToPresentationExchange(q, id, purpose)
	if err != nil {
		return Definition{}, Report{}, err
	}
	var d Definition
	anyval.MustDo(json.Unmarshal(anyval.Must(json.Marshal(pd)), &d))
	d.Name = name
	return d, dcqlLosses(q), nil
}

// dcqlLosses names the parts of a query that PE cannot hold.
func dcqlLosses(q dcql.Query) Report {
	var r Report
	for _, c := range q.Credentials {
		if len(c.TrustedAuthorities) > 0 {
			r.add(LossIssuers, c.ID, "")
		}
		if c.Multiple {
			r.add(LossMultiple, c.ID, "")
		}
		if c.RequireCryptographicHolderBinding != nil && !*c.RequireCryptographicHolderBinding {
			r.add(LossHolderBinding, c.ID, "")
		}
		if !claimSetsKept(c) {
			r.add(LossClaimSets, c.ID, "")
		}
		if c.Meta != nil {
			for _, set := range c.Meta.TypeValues {
				if len(set) > 2 || (len(set) == 2 && set[0] != vcType) {
					r.add(LossTypeValues, c.ID, strings.Join(set, ", "))
				}
			}
		}
		if c.Format == dcql.FormatMdoc {
			for _, cl := range c.Claims {
				if len(cl.Path) != 2 || cl.Path[0].Kind != dcql.KindName || cl.Path[1].Kind != dcql.KindName {
					r.add(LossMdocPath, c.ID, cl.Path.String())
				}
			}
		}
	}
	for i, set := range q.CredentialSets {
		where := fmt.Sprintf("credential_sets/%d", i)
		if !set.IsRequired() {
			r.add(LossOptionalSet, where, "")
			continue
		}
		if len(set.Options) > 1 && slices.ContainsFunc(set.Options, func(o []string) bool { return len(o) > 1 }) {
			r.add(LossSetOptions, where, "")
		}
	}
	return r
}

// vcType is the base type of every W3C credential.
const vcType = "VerifiableCredential"

// claimSetsKept reports whether PE keeps the claim sets of a query. PE
// holds a required part and an optional part. So it keeps no sets, one
// set of every claim, or a first set inside a second set of every claim.
func claimSetsKept(c dcql.CredentialQuery) bool {
	all := make([]string, 0, len(c.Claims))
	for _, cl := range c.Claims {
		all = append(all, cl.ID)
	}
	switch len(c.ClaimSets) {
	case 0:
		return true
	case 1:
		return sameMembers(c.ClaimSets[0], all)
	case 2:
		return sameMembers(c.ClaimSets[1], all) && subset(c.ClaimSets[0], c.ClaimSets[1])
	}
	return false
}

// sameMembers reports whether two lists hold the same members.
func sameMembers(a, b []string) bool {
	return len(a) == len(b) && subset(a, b)
}

// subset reports whether every member of a sits in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// Converted is a DCQL query made from a definition.
type Converted struct {
	// Query is the DCQL query.
	Query dcql.Query
	// Name is the name of the definition.
	Name string
	// Purpose is the purpose of the definition.
	Purpose string
}

// ToDCQL converts a definition into a DCQL query. Pass a definition that
// Validate accepts. The report names every part of the definition that
// the query cannot hold. An error means no query can stand for the
// definition, for example when a descriptor names no known format.
func ToDCQL(d Definition) (Converted, Report, error) {
	var r Report
	if len(d.Frame) > 0 {
		r.add(LossFrame, "/frame", "")
	}
	if hasLimits(d.Format) {
		r.add(LossFormatLimits, "/format", "")
	}
	var q dcql.Query
	ids := map[string]string{}
	taken := map[string]bool{}
	for i, desc := range d.InputDescriptors {
		c, err := credentialOf(desc, d.Format, i, &r)
		if err != nil {
			return Converted{}, Report{}, err
		}
		base := c.ID
		for n := 2; taken[c.ID]; n++ {
			c.ID = fmt.Sprintf("%s_%d", base, n)
		}
		taken[c.ID] = true
		ids[desc.ID] = c.ID
		q.Credentials = append(q.Credentials, c)
	}
	q.CredentialSets = setsOf(d, ids, &r)
	if err := dcql.Validate(q); err != nil {
		return Converted{}, Report{}, err
	}
	return Converted{Query: q, Name: d.Name, Purpose: d.Purpose}, r, nil
}

// credentialOf turns one descriptor into a credential query.
func credentialOf(desc Descriptor, fallback map[string]map[string]any, index int, r *Report) (dcql.CredentialQuery, error) {
	at := fmt.Sprintf("/input_descriptors/%d", index)
	formats, where := desc.Format, at+"/format"
	if len(formats) == 0 {
		formats, where = fallback, "/format"
	} else if hasLimits(formats) {
		r.add(LossFormatLimits, where, "")
	}
	format, count := pickFormat(formats)
	if format == "" {
		return dcql.CredentialQuery{}, fmt.Errorf("pex: the descriptor %q names no credential format that DCQL knows", desc.ID)
	}
	if count > 1 {
		r.add(LossFormat, where, format)
	}
	if desc.Name != "" || desc.Purpose != "" {
		r.add(LossText, at, "")
	}
	cons := desc.Constraints
	if len(cons.Statuses) > 0 {
		r.add(LossStatuses, at+"/constraints/statuses", "")
	}
	if cons.SubjectIsIssuer != "" || len(cons.IsHolder) > 0 || len(cons.SameSubject) > 0 {
		r.add(LossHolderRules, at+"/constraints", "")
	}
	if cons.LimitDisclosure == "required" && !dcql.SelectiveDisclosure(format) {
		r.add(LossLimitDisclosure, at+"/constraints/limit_disclosure", "")
	}
	c := dcql.CredentialQuery{ID: dcql.CleanID(desc.ID), Format: format}
	if c.ID == "" {
		c.ID = fmt.Sprintf("credential%d", index+1)
	}
	var required, optional []string
	typed := false
	for j, f := range cons.Fields {
		fat := fmt.Sprintf("%s/constraints/fields/%d", at, j)
		if isTypeField(f) {
			if typed {
				r.add(LossDuplicate, fat, f.Path[0])
				continue
			}
			typed = true
			c.Meta = metaOf(f.Filter, format, fat, r)
			continue
		}
		path, ok := claimPath(f.Path, format, fat, r)
		if !ok {
			continue
		}
		claim := dcql.ClaimQuery{ID: dcql.CleanID(path.String()), Path: path}
		if slices.ContainsFunc(c.Claims, func(x dcql.ClaimQuery) bool { return x.ID == claim.ID }) {
			r.add(LossDuplicate, fat, path.String())
			continue
		}
		fieldLosses(f, fat, r)
		claim.Values = valuesOf(f.Filter, fat, r)
		c.Claims = append(c.Claims, claim)
		if f.Optional {
			optional = append(optional, claim.ID)
		} else {
			required = append(required, claim.ID)
		}
	}
	switch {
	case len(optional) == 0:
	case len(required) == 0:
		r.add(LossAllOptional, at, "")
	default:
		every := make([]string, 0, len(c.Claims))
		for _, cl := range c.Claims {
			every = append(every, cl.ID)
		}
		c.ClaimSets = [][]string{required, every}
	}
	return c, nil
}

// fieldLosses names the parts of a field that DCQL cannot hold.
func fieldLosses(f Field, at string, r *Report) {
	if f.Name != "" || f.Purpose != "" {
		r.add(LossText, at, "")
	}
	if f.Predicate != "" {
		r.add(LossPredicate, at, "")
	}
	if f.IntentToRetain != nil && *f.IntentToRetain {
		r.add(LossRetain, at, "")
	}
}

// formatNames maps the format names of a definition onto the DCQL
// format, in the order of preference.
var formatNames = []struct{ pe, dcql string }{
	{"dc+sd-jwt", dcql.FormatSDJWT},
	{"vc+sd-jwt", dcql.FormatSDJWTLegacy},
	{"jwt_vc_json", dcql.FormatJWTVCJSON},
	{"jwt_vc", dcql.FormatJWTVCJSON},
	{"jwt", dcql.FormatJWTVCJSON},
	{"ldp_vc", dcql.FormatLDPVC},
	{"ldp", dcql.FormatLDPVC},
	{"mso_mdoc", dcql.FormatMdoc},
}

// presentationFormats are the format names of a presentation, not of a
// credential. A descriptor may name them beside the credential format.
var presentationFormats = []string{"jwt_vp", "jwt_vp_json", "ldp_vp", "ac_vp"}

// pickFormat returns the preferred DCQL format of a format map and the
// number of distinct credential formats the map names.
func pickFormat(formats map[string]map[string]any) (string, int) {
	found := ""
	distinct := map[string]bool{}
	for _, f := range formatNames {
		if _, ok := formats[f.pe]; ok {
			distinct[f.dcql] = true
			if found == "" {
				found = f.dcql
			}
		}
	}
	count := len(distinct)
	for name := range formats {
		known := slices.ContainsFunc(formatNames, func(f struct{ pe, dcql string }) bool { return f.pe == name })
		if !known && !slices.Contains(presentationFormats, name) {
			count++
		}
	}
	return found, count
}

// hasLimits reports whether a format map limits an algorithm or a proof
// type.
func hasLimits(formats map[string]map[string]any) bool {
	for _, limits := range formats {
		if len(limits) > 0 {
			return true
		}
	}
	return false
}

// typePaths are the paths that hold the credential type.
var typePaths = []string{"$.type", "$.vc.type", "$.vct", "$.docType"}

// isTypeField reports whether a field filters the credential type.
func isTypeField(f Field) bool {
	return len(f.Path) > 0 && slices.Contains(typePaths, f.Path[0])
}

// plainWord matches a pattern that is a literal type name.
var plainWord = regexp.MustCompile(`^[A-Za-z0-9_.:/#-]+$`)

// metaOf reads the type of a type field filter.
func metaOf(filter any, format, at string, r *Report) *dcql.Meta {
	names, rest := typeNames(filter)
	if len(names) == 0 {
		r.add(LossTypeFilter, at, strings.Join(append(rest, "type"), ", "))
		return nil
	}
	if len(rest) > 0 {
		r.add(LossTypeFilter, at, strings.Join(rest, ", "))
	}
	switch format {
	case dcql.FormatSDJWT, dcql.FormatSDJWTLegacy:
		return &dcql.Meta{VctValues: names}
	case dcql.FormatMdoc:
		if len(names) > 1 {
			r.add(LossTypeFilter, at, names[0])
		}
		return &dcql.Meta{DoctypeValue: names[0]}
	}
	m := &dcql.Meta{}
	for _, n := range names {
		set := []string{vcType, n}
		if n == vcType {
			set = []string{vcType}
		}
		m.TypeValues = append(m.TypeValues, set)
	}
	return m
}

// typeNames reads the type names of a filter and the keywords it could
// not read.
func typeNames(filter any) ([]string, []string) {
	m, ok := filter.(map[string]any)
	if !ok {
		return nil, []string{"filter"}
	}
	var names, rest []string
	for _, key := range sortedKeys(m) {
		switch key {
		case "type":
		case "const":
			names = append(names, texts([]any{m[key]})...)
		case "enum":
			names = append(names, texts(anyval.As[[]any](m[key]))...)
		case "contains":
			inner, innerRest := typeNames(m[key])
			names, rest = append(names, inner...), append(rest, innerRest...)
		case "pattern":
			rest = append(rest, key)
			if p, isText := m[key].(string); isText && plainWord.MatchString(p) {
				names = append(names, p)
			}
		default:
			rest = append(rest, key)
		}
	}
	return names, rest
}

// texts returns the strings of a list.
func texts(list []any) []string {
	var out []string
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// claimPath reads the DCQL claims path of a field. It takes the first
// path that DCQL can hold and names the rest when they point elsewhere.
func claimPath(paths []string, format, at string, r *Report) (dcql.Path, bool) {
	var kept dcql.Path
	other := false
	for _, text := range paths {
		p, ok := relative(text, format)
		switch {
		case !ok:
			other = true
		case kept == nil:
			kept = p
		case p.String() != kept.String():
			other = true
		}
	}
	if kept == nil {
		r.add(LossPath, at, strings.Join(paths, ", "))
		return nil, false
	}
	if other {
		r.add(LossAltPaths, at, kept.JSONPath(dcql.ClaimPrefix(format)))
	}
	return kept, true
}

// relative returns the claim path of a JSONPath below the claims of a
// format: the root of an SD-JWT VC, the credentialSubject of a W3C
// credential, or a namespace and a name of a mobile document.
func relative(text, format string) (dcql.Path, bool) {
	p, err := ParseJSONPath(text)
	if err != nil {
		return nil, false
	}
	var prefixes []string
	switch format {
	case dcql.FormatJWTVCJSON:
		prefixes = []string{"vc.credentialSubject", "credentialSubject"}
	case dcql.FormatLDPVC:
		prefixes = []string{"credentialSubject"}
	default:
		prefixes = []string{""}
	}
	for _, prefix := range prefixes {
		if rest, ok := cut(p, prefix); ok && len(rest) > 0 {
			if format == dcql.FormatMdoc && (len(rest) != 2 || rest[0].Kind != dcql.KindName || rest[1].Kind != dcql.KindName) {
				return nil, false
			}
			return rest, true
		}
	}
	return nil, false
}

// cut removes a dotted prefix of names from a path.
func cut(p dcql.Path, prefix string) (dcql.Path, bool) {
	if prefix == "" {
		return p, true
	}
	names := strings.Split(prefix, ".")
	if len(p) < len(names) {
		return nil, false
	}
	for i, n := range names {
		if p[i].Kind != dcql.KindName || p[i].Name != n {
			return nil, false
		}
	}
	return p[len(names):], true
}

// valuesOf reads the accepted values of a claim filter: const or enum.
// A type that every value matches adds nothing. Every other keyword is
// a loss.
func valuesOf(filter any, at string, r *Report) []any {
	if filter == nil {
		return nil
	}
	m, ok := filter.(map[string]any)
	if !ok {
		r.add(LossFilter, at, "boolean")
		return nil
	}
	used := map[string]bool{}
	var values []any
	if c, has := m["const"]; has {
		values, used["const"] = []any{c}, true
	} else if list := anyval.As[[]any](m["enum"]); len(list) > 0 {
		values, used["enum"] = slices.Clone(list), true
	}
	if slices.ContainsFunc(values, func(v any) bool { return !scalar(v) }) {
		values, used = nil, map[string]bool{}
	}
	if values != nil && everyOfType(values, m["type"]) {
		used["type"] = true
	}
	var rest []string
	for _, key := range sortedKeys(m) {
		if !used[key] {
			rest = append(rest, key)
		}
	}
	if len(rest) > 0 {
		r.add(LossFilter, at, strings.Join(rest, ", "))
	}
	return values
}

// scalar reports whether DCQL can hold a value: a string, a whole
// number, or a boolean.
func scalar(v any) bool {
	switch x := v.(type) {
	case string, bool:
		return true
	case float64:
		return x == math.Trunc(x)
	}
	return false
}

// everyOfType reports whether every value has the JSON Schema type.
func everyOfType(values []any, kind any) bool {
	for _, v := range values {
		var ok bool
		switch kind {
		case "string":
			_, ok = v.(string)
		case "boolean":
			_, ok = v.(bool)
		case "integer", "number":
			_, ok = v.(float64)
		}
		if !ok {
			return false
		}
	}
	return true
}

// setsOf turns the submission requirements into credential sets. A
// descriptor that no requirement names becomes an optional set.
func setsOf(d Definition, ids map[string]string, r *Report) []dcql.CredentialSetQuery {
	if len(d.SubmissionRequirements) == 0 {
		return nil
	}
	groups := map[string][]string{}
	for _, desc := range d.InputDescriptors {
		for _, g := range desc.Group {
			groups[g] = append(groups[g], ids[desc.ID])
		}
	}
	used := map[string]bool{}
	var out []dcql.CredentialSetQuery
	for i, sr := range d.SubmissionRequirements {
		out = append(out, requirementSets(sr, fmt.Sprintf("/submission_requirements/%d", i), groups, used, r)...)
	}
	no := false
	for _, desc := range d.InputDescriptors {
		if id := ids[desc.ID]; !used[id] {
			out = append(out, dcql.CredentialSetQuery{Options: [][]string{{id}}, Required: &no})
		}
	}
	return out
}

// requirementSets turns one requirement into credential sets.
func requirementSets(sr Requirement, at string, groups map[string][]string, used map[string]bool, r *Report) []dcql.CredentialSetQuery {
	if sr.Name != "" {
		r.add(LossText, at, "")
	}
	if len(sr.FromNested) > 0 {
		r.add(LossNested, at, "")
		var out []dcql.CredentialSetQuery
		for i, inner := range sr.FromNested {
			out = append(out, requirementSets(inner, fmt.Sprintf("%s/from_nested/%d", at, i), groups, used, r)...)
		}
		return out
	}
	members := groups[sr.From]
	for _, id := range members {
		used[id] = true
	}
	set := dcql.CredentialSetQuery{Purpose: sr.Purpose, Options: [][]string{members}}
	if sr.Rule != RulePick {
		return []dcql.CredentialSetQuery{set}
	}
	low, high := 0, len(members)
	if sr.Count != nil {
		low, high = *sr.Count, *sr.Count
	}
	if sr.Min != nil {
		low = *sr.Min
	}
	if sr.Max != nil {
		high = min(*sr.Max, high)
	}
	if low == 0 {
		no := false
		set.Required, low = &no, 1
	}
	var options [][]string
	for size := low; size <= high; size++ {
		options = append(options, combinations(members, size)...)
	}
	if len(options) == 0 || len(options) > MaxOptions {
		r.add(LossPick, at, "")
		return []dcql.CredentialSetQuery{set}
	}
	set.Options = options
	return []dcql.CredentialSetQuery{set}
}

// combinations returns every choice of size members, in member order.
func combinations(members []string, size int) [][]string {
	if size == 0 {
		return [][]string{{}}
	}
	var out [][]string
	for i := 0; i+size <= len(members); i++ {
		for _, rest := range combinations(members[i+1:], size-1) {
			out = append(out, append([]string{members[i]}, rest...))
		}
		if len(out) > MaxOptions {
			return out
		}
	}
	return out
}
