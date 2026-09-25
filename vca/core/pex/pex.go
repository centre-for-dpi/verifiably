// SPDX-License-Identifier: Apache-2.0

// Package pex holds DIF Presentation Exchange 2.0 for the verifier
// (ADR-042 decisions 4 and 5). Some stacks still read a presentation
// definition and not a DCQL query. Staff author or import a definition,
// the package validates it against the vendored PE 2.0 JSON Schema, and
// it converts a definition to and from a DCQL query of core/dcql.
//
// A conversion never hides a lost part. It returns a Report with one
// Loss for each part the other language cannot hold, for example a
// status directive or a pattern filter.
//
// The package is pure. It parses, validates, converts, and serialises.
// It never performs input or output.
package pex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// MaxDefinitionBytes caps the JSON text of one definition.
const MaxDefinitionBytes = 256 << 10

// Definition is a Presentation Exchange 2.0 presentation definition.
type Definition struct {
	// ID names the definition.
	ID string `json:"id"`
	// Name is the display name, when any.
	Name string `json:"name,omitempty"`
	// Purpose is the reason the verifier gives the holder.
	Purpose string `json:"purpose,omitempty"`
	// Format limits the formats of every descriptor, keyed by format.
	Format map[string]map[string]any `json:"format,omitempty"`
	// Frame is a JSON-LD frame, when any.
	Frame map[string]any `json:"frame,omitempty"`
	// SubmissionRequirements say which descriptors satisfy the request.
	SubmissionRequirements []Requirement `json:"submission_requirements,omitempty"`
	// InputDescriptors hold one entry for each credential.
	InputDescriptors []Descriptor `json:"input_descriptors"`
}

// Requirement is one submission requirement.
type Requirement struct {
	// Name is the display name, when any.
	Name string `json:"name,omitempty"`
	// Purpose is the reason for the requirement.
	Purpose string `json:"purpose,omitempty"`
	// Rule is RuleAll or RulePick.
	Rule string `json:"rule"`
	// Count is the number of descriptors a pick rule needs.
	Count *int `json:"count,omitempty"`
	// Min is the least number of descriptors a pick rule needs.
	Min *int `json:"min,omitempty"`
	// Max is the largest number of descriptors a pick rule takes.
	Max *int `json:"max,omitempty"`
	// From names the group of descriptors.
	From string `json:"from,omitempty"`
	// FromNested holds inner requirements instead of a group.
	FromNested []Requirement `json:"from_nested,omitempty"`
}

// Rules of a submission requirement.
const (
	RuleAll  = "all"
	RulePick = "pick"
)

// Descriptor asks for one credential.
type Descriptor struct {
	// ID names the descriptor.
	ID string `json:"id"`
	// Name is the display name, when any.
	Name string `json:"name,omitempty"`
	// Purpose is the reason for the descriptor.
	Purpose string `json:"purpose,omitempty"`
	// Group holds the groups of the descriptor.
	Group []string `json:"group,omitempty"`
	// Format limits the formats of the descriptor, keyed by format.
	Format map[string]map[string]any `json:"format,omitempty"`
	// Constraints holds the field rules.
	Constraints Constraints `json:"constraints"`
}

// Constraints limit what the holder discloses.
type Constraints struct {
	// LimitDisclosure is required or preferred.
	LimitDisclosure string `json:"limit_disclosure,omitempty"`
	// Statuses holds the status directives, keyed by status.
	Statuses map[string]any `json:"statuses,omitempty"`
	// Fields lists the claim rules.
	Fields []Field `json:"fields,omitempty"`
	// SubjectIsIssuer asks for a self issued credential.
	SubjectIsIssuer string `json:"subject_is_issuer,omitempty"`
	// IsHolder asks the holder to prove it is the subject of fields.
	IsHolder []HolderDirective `json:"is_holder,omitempty"`
	// SameSubject asks that fields share one subject.
	SameSubject []HolderDirective `json:"same_subject,omitempty"`
}

// HolderDirective is one is_holder or same_subject entry.
type HolderDirective struct {
	// FieldID lists the ids of the fields.
	FieldID []string `json:"field_id"`
	// Directive is required or preferred.
	Directive string `json:"directive"`
}

// Field is one claim rule.
type Field struct {
	// ID names the field, for the holder directives.
	ID string `json:"id,omitempty"`
	// Path lists the JSONPath expressions that may hold the claim.
	Path []string `json:"path"`
	// Purpose is the reason for the field.
	Purpose string `json:"purpose,omitempty"`
	// Name is the display name, when any.
	Name string `json:"name,omitempty"`
	// Filter is a JSON Schema the value must match. It is an object or
	// a boolean.
	Filter any `json:"filter,omitempty"`
	// Predicate asks for a yes or no answer instead of the value.
	Predicate string `json:"predicate,omitempty"`
	// Optional marks a claim the holder may leave out.
	Optional bool `json:"optional,omitempty"`
	// IntentToRetain says that the verifier keeps the claim.
	IntentToRetain *bool `json:"intent_to_retain,omitempty"`
}

// Problem is one reason a definition is not valid.
type Problem struct {
	// Path is the JSON Pointer of the value, "" for the root.
	Path string
	// Keyword is the schema keyword that failed, for example required,
	// or "rule" for a rule the schema cannot hold.
	Keyword string
	// Message says what is wrong.
	Message string
}

// Error formats the problem as "<path>: <message>".
func (p Problem) Error() string {
	path := p.Path
	if path == "" {
		path = "/"
	}
	return path + ": " + p.Message
}

// ErrTooLarge reports a definition above MaxDefinitionBytes.
var ErrTooLarge = errors.New("pex: the definition is larger than 256 KiB")

// Validate reads a definition and checks it against the PE 2.0 schema
// and the rules the schema cannot hold. It returns the definition and
// every problem. The definition holds what the text has, even when a
// problem exists, so the page can show it again.
func Validate(raw []byte) (Definition, []Problem) {
	if len(raw) > MaxDefinitionBytes {
		return Definition{}, []Problem{{Keyword: "size", Message: ErrTooLarge.Error()}}
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return Definition{}, []Problem{{Keyword: "json", Message: fmt.Sprintf("the text is not JSON: %v", err)}}
	}
	if dec.More() {
		return Definition{}, []Problem{{Keyword: "json", Message: "the text holds more than one JSON value"}}
	}
	problems := schemaProblems(doc)
	var d Definition
	if err := json.Unmarshal(raw, &d); err != nil {
		if len(problems) == 0 {
			problems = append(problems, Problem{Keyword: "json", Message: err.Error()})
		}
		return Definition{}, problems
	}
	if len(problems) > 0 {
		return d, problems
	}
	return d, rules(d)
}

// rules checks what the schema cannot: at least one descriptor, unique
// descriptor ids, JSONPath expressions that start at the root, and
// requirements that name an existing group.
func rules(d Definition) []Problem {
	var out []Problem
	if len(d.InputDescriptors) == 0 {
		out = append(out, Problem{Keyword: "rule", Path: "/input_descriptors", Message: "the definition asks for no credential"})
	}
	seen := map[string]bool{}
	groups := map[string]bool{}
	for i, desc := range d.InputDescriptors {
		at := fmt.Sprintf("/input_descriptors/%d", i)
		if desc.ID == "" {
			out = append(out, Problem{Keyword: "rule", Path: at + "/id", Message: "the descriptor id is empty"})
		}
		if seen[desc.ID] {
			out = append(out, Problem{Keyword: "rule", Path: at + "/id", Message: fmt.Sprintf("the descriptor id %q is used twice", desc.ID)})
		}
		seen[desc.ID] = true
		for _, g := range desc.Group {
			groups[g] = true
		}
		for j, f := range desc.Constraints.Fields {
			if len(f.Path) == 0 {
				out = append(out, Problem{Keyword: "rule", Path: fmt.Sprintf("%s/constraints/fields/%d/path", at, j), Message: "the field has no path"})
			}
			for k, p := range f.Path {
				if len(p) == 0 || p[0] != '$' {
					out = append(out, Problem{Keyword: "rule", Path: fmt.Sprintf("%s/constraints/fields/%d/path/%d", at, j, k), Message: fmt.Sprintf("the JSONPath %q does not start at the root $", p)})
				}
			}
		}
	}
	for i, r := range d.SubmissionRequirements {
		out = append(out, requirementRules(r, fmt.Sprintf("/submission_requirements/%d", i), groups)...)
	}
	return out
}

// requirementRules checks one requirement and its inner requirements.
func requirementRules(r Requirement, at string, groups map[string]bool) []Problem {
	var out []Problem
	if r.From != "" && !groups[r.From] {
		out = append(out, Problem{Keyword: "rule", Path: at + "/from", Message: fmt.Sprintf("no descriptor sits in the group %q", r.From)})
	}
	for i, inner := range r.FromNested {
		out = append(out, requirementRules(inner, fmt.Sprintf("%s/from_nested/%d", at, i), groups)...)
	}
	return out
}

// Marshal writes a definition as JSON. A definition holds only values
// that JSON holds, so the write cannot fail.
func Marshal(d Definition) []byte {
	return anyval.Must(json.Marshal(d))
}
