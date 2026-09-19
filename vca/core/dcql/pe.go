// SPDX-License-Identifier: Apache-2.0

package dcql

import (
	"encoding/json"
	"fmt"
)

// Presentation Exchange 2.0 is the older query language. Some Digital
// Public Goods still need it, for example walt.id 0.18 (ADR-022
// decision 3). PresentationDefinition generates it from a DCQL query.

// PresentationDefinition is a Presentation Exchange 2.0 definition.
type PresentationDefinition struct {
	// ID names the definition.
	ID string `json:"id"`
	// Name is the display name, when any.
	Name string `json:"name,omitempty"`
	// Purpose is the reason the verifier gives the citizen.
	Purpose string `json:"purpose,omitempty"`
	// InputDescriptors holds one entry for each credential.
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
	// SubmissionRequirements says which descriptors satisfy the request.
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty"`
}

// InputDescriptor asks for one credential.
type InputDescriptor struct {
	// ID names the descriptor. It matches the DCQL credential query id.
	ID string `json:"id"`
	// Name is the display name, when any.
	Name string `json:"name,omitempty"`
	// Group holds the submission requirement groups of the descriptor.
	Group []string `json:"group,omitempty"`
	// Format maps the wire format to its algorithm limits.
	Format map[string]map[string]any `json:"format"`
	// Constraints holds the field rules.
	Constraints Constraints `json:"constraints"`
}

// Constraints limits the claims the wallet discloses.
type Constraints struct {
	// LimitDisclosure is required or preferred.
	LimitDisclosure string `json:"limit_disclosure,omitempty"`
	// Fields lists the claims the verifier asks for.
	Fields []Field `json:"fields"`
}

// Field is one claim rule.
type Field struct {
	// Path holds the JSONPath expressions that may hold the claim.
	Path []string `json:"path"`
	// Filter is a JSON Schema fragment the value must match.
	Filter map[string]any `json:"filter,omitempty"`
	// Optional marks a claim the wallet may leave out.
	Optional bool `json:"optional,omitempty"`
	// IntentToRetain says whether the verifier stores the claim. Mobile
	// documents need it.
	IntentToRetain *bool `json:"intent_to_retain,omitempty"`
}

// SubmissionRequirement says how many descriptors of a group must match.
type SubmissionRequirement struct {
	// Name is the display name, when any.
	Name string `json:"name,omitempty"`
	// Purpose is the reason the verifier gives the citizen.
	Purpose string `json:"purpose,omitempty"`
	// Rule is all or pick.
	Rule string `json:"rule"`
	// Count is the number of descriptors a pick rule needs.
	Count int `json:"count,omitempty"`
	// From names the group the rule applies to.
	From string `json:"from"`
}

// Rules of Presentation Exchange 2.0.
const (
	RuleAll  = "all"
	RulePick = "pick"
)

// ToPresentationExchange generates a Presentation Exchange 2.0 definition
// from a DCQL query. id names the definition.
func ToPresentationExchange(q Query, id, purpose string) (PresentationDefinition, error) {
	if err := Validate(q); err != nil {
		return PresentationDefinition{}, err
	}
	if id == "" {
		return PresentationDefinition{}, fmt.Errorf("dcql: the presentation definition needs an id")
	}
	groups := groupsOf(q)
	pd := PresentationDefinition{ID: id, Purpose: purpose}
	for _, c := range q.Credentials {
		pd.InputDescriptors = append(pd.InputDescriptors, descriptorOf(c, groups[c.ID]))
	}
	pd.SubmissionRequirements = requirementsOf(q, purpose)
	return pd, nil
}

// MarshalPresentationExchange generates the definition and writes it as JSON.
func MarshalPresentationExchange(q Query, id, purpose string) ([]byte, error) {
	pd, err := ToPresentationExchange(q, id, purpose)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pd)
}

// groupsOf returns the submission requirement groups of each credential
// query id. One group exists for each credential set.
func groupsOf(q Query) map[string][]string {
	out := map[string][]string{}
	for i, set := range q.CredentialSets {
		name := fmt.Sprintf("group%d", i+1)
		for _, option := range set.Options {
			for _, id := range option {
				if !known(out[id], name) {
					out[id] = append(out[id], name)
				}
			}
		}
	}
	return out
}

// requirementsOf turns the credential sets into submission requirements.
// A set with one option becomes an all rule. A set with more options
// becomes a pick rule of one.
func requirementsOf(q Query, purpose string) []SubmissionRequirement {
	var out []SubmissionRequirement
	for i, set := range q.CredentialSets {
		if !set.IsRequired() {
			continue
		}
		reason := set.Purpose
		if reason == "" {
			reason = purpose
		}
		r := SubmissionRequirement{Rule: RuleAll, From: fmt.Sprintf("group%d", i+1), Purpose: reason}
		if len(set.Options) > 1 {
			r.Rule, r.Count = RulePick, 1
		}
		out = append(out, r)
	}
	return out
}

// descriptorOf turns one credential query into an input descriptor.
func descriptorOf(c CredentialQuery, groups []string) InputDescriptor {
	d := InputDescriptor{
		ID:     c.ID,
		Group:  groups,
		Format: map[string]map[string]any{c.Format: {}},
		Constraints: Constraints{
			LimitDisclosure: "preferred",
			Fields:          []Field{},
		},
	}
	if SelectiveDisclosure(c.Format) {
		d.Constraints.LimitDisclosure = "required"
	}
	if t := c.Type(); t != "" {
		d.Constraints.Fields = append(d.Constraints.Fields, Field{
			Path:   []string{TypePath(c.Format)},
			Filter: typeFilter(c),
		})
	}
	optional := map[string]bool{}
	for _, set := range c.ClaimSets {
		for _, id := range set {
			optional[id] = true
		}
	}
	for _, cl := range c.Claims {
		d.Constraints.Fields = append(d.Constraints.Fields, fieldOf(c, cl, optionalClaim(c, cl, optional)))
	}
	return d
}

// optionalClaim reports whether a claim sits outside the first claim set.
// A claim the first, most preferred set leaves out is optional.
func optionalClaim(c CredentialQuery, cl ClaimQuery, used map[string]bool) bool {
	if len(c.ClaimSets) == 0 || cl.ID == "" {
		return false
	}
	if !used[cl.ID] {
		return true
	}
	return !known(c.ClaimSets[0], cl.ID)
}

// fieldOf turns one claim query into a field rule.
func fieldOf(c CredentialQuery, cl ClaimQuery, optional bool) Field {
	f := Field{Optional: optional}
	if c.Format == FormatMdoc && len(cl.Path) == 2 {
		f.Path = []string{quoted(cl.Path[0].Name, cl.Path[1].Name)}
		retain := false
		f.IntentToRetain = &retain
	} else {
		f.Path = []string{cl.Path.JSONPath(ClaimPrefix(c.Format))}
	}
	if len(cl.Values) > 0 {
		f.Filter = map[string]any{"enum": cl.Values}
	}
	return f
}

// typeFilter returns the JSON Schema fragment of the type filter.
func typeFilter(c CredentialQuery) map[string]any {
	switch c.Format {
	case FormatSDJWT, FormatSDJWTLegacy:
		return enumFilter(c.Meta.VctValues)
	case FormatMdoc:
		return map[string]any{"type": "string", "const": c.Meta.DoctypeValue}
	default:
		var names []string
		for _, set := range c.Meta.TypeValues {
			names = append(names, set[len(set)-1])
		}
		return map[string]any{"type": "array", "contains": enumFilter(names)}
	}
}

// enumFilter returns a string filter that accepts every value.
func enumFilter(values []string) map[string]any {
	if len(values) == 1 {
		return map[string]any{"type": "string", "const": values[0]}
	}
	list := make([]any, 0, len(values))
	for _, v := range values {
		list = append(list, v)
	}
	return map[string]any{"type": "string", "enum": list}
}
