// SPDX-License-Identifier: Apache-2.0

// Package table is the common shape every source produces: an ordered
// list of field names and rows of string values. It infers field types
// and masks values for previews (ADR-015 decision 4). It is pure.
package table

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Table is the output of one read of a source.
type Table struct {
	// Fields are the field names in source order.
	Fields []string
	// Rows are the values keyed by field name.
	Rows []map[string]string
	// Total is the number of rows in the source, when the source knows it.
	// Zero means unknown.
	Total int64
}

// Type names an inferred field type.
type Type string

// Types the package infers.
const (
	String  Type = "string"
	Number  Type = "number"
	Integer Type = "integer"
	Boolean Type = "boolean"
	Date    Type = "date"
)

// Field is one inferred field.
type Field struct {
	Name    string
	Type    Type
	Example string
}

// dateLayouts are the layouts InferType accepts as a date.
var dateLayouts = []string{"2006-01-02", time.RFC3339, "02/01/2006", "2006-01-02 15:04:05"}

// InferType returns the narrowest type every non empty value fits.
// No non empty value gives String.
func InferType(values []string) Type {
	seen := false
	isInt, isNum, isBool, isDate := true, true, true, true
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		seen = true
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			isInt = false
		}
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			isNum = false
		}
		if _, err := strconv.ParseBool(v); err != nil || !isBoolWord(v) {
			isBool = false
		}
		if !isDateValue(v) {
			isDate = false
		}
	}
	switch {
	case !seen:
		return String
	case isBool:
		return Boolean
	case isInt:
		return Integer
	case isNum:
		return Number
	case isDate:
		return Date
	}
	return String
}

func isBoolWord(v string) bool {
	switch strings.ToLower(v) {
	case "true", "false":
		return true
	}
	return false
}

func isDateValue(v string) bool {
	for _, l := range dateLayouts {
		if _, err := time.Parse(l, v); err == nil {
			return true
		}
	}
	return false
}

// FieldsOf returns the union of the keys of rows. Names in preferred
// come first in that order. The rest follow sorted.
func FieldsOf(rows []map[string]string, preferred []string) []string {
	present := map[string]bool{}
	for _, r := range rows {
		for k := range r {
			present[k] = true
		}
	}
	out := make([]string, 0, len(present))
	seen := map[string]bool{}
	for _, k := range preferred {
		if present[k] && !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range present {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// Infer returns one Field per field of t from at most sample rows.
// The example is the first non empty value, masked with m.
func Infer(t Table, sample int, m Masker) []Field {
	rows := Limit(t.Rows, sample)
	out := make([]Field, 0, len(t.Fields))
	for _, name := range t.Fields {
		values := make([]string, 0, len(rows))
		example := ""
		for _, r := range rows {
			v := r[name]
			values = append(values, v)
			if example == "" && strings.TrimSpace(v) != "" {
				example = v
			}
		}
		out = append(out, Field{Name: name, Type: InferType(values), Example: m.Mask(example)})
	}
	return out
}

// Limit returns at most n rows. n zero or less returns no rows.
func Limit(rows []map[string]string, n int) []map[string]string {
	if n <= 0 {
		return nil
	}
	if len(rows) > n {
		return rows[:n]
	}
	return rows
}

// Masker hides the middle of a value.
type Masker struct {
	// Head is the number of leading characters that stay visible.
	Head int
	// Tail is the number of trailing characters that stay visible.
	Tail int
}

// DefaultMasker keeps the first and the last character.
var DefaultMasker = Masker{Head: 1, Tail: 1}

// Mask returns v with every character between Head and Tail replaced by
// an asterisk. A value that is not longer than Head plus Tail is fully
// masked.
func (m Masker) Mask(v string) string {
	r := []rune(v)
	n := len(r)
	if n == 0 {
		return ""
	}
	if n <= m.Head+m.Tail {
		return strings.Repeat("*", n)
	}
	return string(r[:m.Head]) + strings.Repeat("*", n-m.Head-m.Tail) + string(r[n-m.Tail:])
}

// MaskRows returns a copy of rows with every value masked.
func (m Masker) MaskRows(rows []map[string]string) []map[string]string {
	out := make([]map[string]string, len(rows))
	for i, r := range rows {
		mr := make(map[string]string, len(r))
		for k, v := range r {
			mr[k] = m.Mask(v)
		}
		out[i] = mr
	}
	return out
}
