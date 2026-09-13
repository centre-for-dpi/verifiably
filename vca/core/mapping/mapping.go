// SPDX-License-Identifier: Apache-2.0

// Package mapping fills schema properties from source rows
// (ADR-015 decision 5). A FieldMap holds one Rule per property. A rule
// reads one or more source fields and applies one Transform.
//
// The package is pure. Apply reads a row and returns a new map. It never
// changes the row and keeps no state.
package mapping

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Transform names a pure function that a rule applies.
type Transform string

// Transforms the package supports.
const (
	// Copy uses the source value as is.
	Copy Transform = ""
	// Trim removes leading and trailing white space.
	Trim Transform = "trim"
	// DateFormat parses the value with params["input_layout"] and formats
	// it with params["output_layout"]. Both are Go time layouts.
	DateFormat Transform = "date_format"
	// Constant uses params["value"] and reads no source field.
	Constant Transform = "constant"
	// Concat joins every source field with params["separator"].
	Concat Transform = "concat"
	// Upper changes the value to upper case.
	Upper Transform = "upper"
	// Lower changes the value to lower case.
	Lower Transform = "lower"
)

// Parameter names the transforms read.
const (
	ParamInputLayout  = "input_layout"
	ParamOutputLayout = "output_layout"
	ParamValue        = "value"
	ParamSeparator    = "separator"
)

// Errors the package returns. Callers match them with errors.Is.
var (
	ErrEmptyProperty    = errors.New("mapping: a rule has no property")
	ErrDuplicateRule    = errors.New("mapping: two rules fill the same property")
	ErrNoSourceField    = errors.New("mapping: a rule reads no source field")
	ErrTooManyFields    = errors.New("mapping: a rule reads more than one source field")
	ErrUnknownTransform = errors.New("mapping: unknown transform")
	ErrMissingParam     = errors.New("mapping: a transform parameter is missing")
	ErrMissingField     = errors.New("mapping: the row has no such field")
	ErrBadDate          = errors.New("mapping: the value does not match the input layout")
)

// Rule fills one schema property.
type Rule struct {
	// Property is the schema property name.
	Property string `json:"property"`
	// SourceFields are the source field names. One field, or several for
	// Concat. Empty for Constant.
	SourceFields []string `json:"source_fields,omitempty"`
	// Transform is the function to apply. Copy uses the value as is.
	Transform Transform `json:"transform,omitempty"`
	// Params are the transform parameters.
	Params map[string]string `json:"params,omitempty"`
}

// FieldMap maps the fields of one source to the properties of one schema.
type FieldMap struct {
	SourceID      string `json:"source_id"`
	SchemaID      string `json:"schema_id"`
	SchemaVersion int    `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}

// Validate checks every rule. It returns the first problem.
func (fm FieldMap) Validate() error {
	seen := map[string]bool{}
	for _, r := range fm.Rules {
		if err := r.Validate(); err != nil {
			return err
		}
		if seen[r.Property] {
			return fmt.Errorf("%w: %s", ErrDuplicateRule, r.Property)
		}
		seen[r.Property] = true
	}
	return nil
}

// Validate checks one rule.
func (r Rule) Validate() error {
	if r.Property == "" {
		return ErrEmptyProperty
	}
	switch r.Transform {
	case Copy, Trim, Upper, Lower:
		return r.wantFields(1, 1)
	case DateFormat:
		if err := r.wantFields(1, 1); err != nil {
			return err
		}
		return r.wantParams(ParamInputLayout, ParamOutputLayout)
	case Constant:
		return r.wantParams(ParamValue)
	case Concat:
		return r.wantFields(1, 0)
	}
	return fmt.Errorf("%w: %q on %s", ErrUnknownTransform, r.Transform, r.Property)
}

// wantFields checks the field count. max zero means no upper bound.
func (r Rule) wantFields(min, max int) error {
	if len(r.SourceFields) < min {
		return fmt.Errorf("%w: %s", ErrNoSourceField, r.Property)
	}
	if max > 0 && len(r.SourceFields) > max {
		return fmt.Errorf("%w: %s", ErrTooManyFields, r.Property)
	}
	return nil
}

func (r Rule) wantParams(names ...string) error {
	for _, n := range names {
		if _, ok := r.Params[n]; !ok {
			return fmt.Errorf("%w: %s needs %s", ErrMissingParam, r.Property, n)
		}
	}
	return nil
}

// Apply fills the schema properties of fm from row. Every value in the
// result is a string. Apply validates fm first.
func Apply(row map[string]string, fm FieldMap) (map[string]any, error) {
	if err := fm.Validate(); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(fm.Rules))
	for _, r := range fm.Rules {
		v, err := applyRule(row, r)
		if err != nil {
			return nil, err
		}
		out[r.Property] = v
	}
	return out, nil
}

func applyRule(row map[string]string, r Rule) (string, error) {
	if r.Transform == Constant {
		return r.Params[ParamValue], nil
	}
	values := make([]string, 0, len(r.SourceFields))
	for _, f := range r.SourceFields {
		v, ok := row[f]
		if !ok {
			return "", fmt.Errorf("%w: %s for %s", ErrMissingField, f, r.Property)
		}
		values = append(values, v)
	}
	switch r.Transform {
	case Trim:
		return strings.TrimSpace(values[0]), nil
	case Upper:
		return strings.ToUpper(values[0]), nil
	case Lower:
		return strings.ToLower(values[0]), nil
	case Concat:
		return strings.Join(values, r.Params[ParamSeparator]), nil
	case DateFormat:
		t, err := time.Parse(r.Params[ParamInputLayout], strings.TrimSpace(values[0]))
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrBadDate, r.Property)
		}
		return t.Format(r.Params[ParamOutputLayout]), nil
	}
	return values[0], nil
}

// Unmapped returns the properties that no rule of fm fills, sorted.
func Unmapped(fm FieldMap, properties []string) []string {
	filled := make(map[string]bool, len(fm.Rules))
	for _, r := range fm.Rules {
		filled[r.Property] = true
	}
	var out []string
	for _, p := range properties {
		if !filled[p] {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// SourceFields returns every source field the rules of fm read, sorted
// and without duplicates.
func SourceFields(fm FieldMap) []string {
	set := map[string]bool{}
	for _, r := range fm.Rules {
		for _, f := range r.SourceFields {
			set[f] = true
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
