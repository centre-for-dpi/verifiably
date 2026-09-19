// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// The CLI reads the rule of a setting from the validation text of the
// proto option. One sentence pattern maps to one check. No rule lives
// twice, so the proto stays the only source (ADR-007 decision 6).
var (
	rxOneOf      = regexp.MustCompile(`one of ([a-z0-9_, ]+?)\s*\.`)
	rxStartsWith = regexp.MustCompile(`starts with ([a-z0-9]+://(?: or [a-z0-9]+://)*)`)
	rxCommaList  = regexp.MustCompile(`comma separated list of ([a-z0-9, ]+?(?: and [a-z0-9]+)?)\s*\.`)
	rxBetween    = regexp.MustCompile(`between (\d+) and (\d+)`)
	rxScheme     = regexp.MustCompile(`[a-z0-9]+://`)
)

// ValidationError reports one value that breaks the rule of a setting.
type ValidationError struct {
	// Env is the environment variable name of the setting.
	Env string
	// Reason says what is wrong, in one sentence.
	Reason string
}

func (e *ValidationError) Error() string { return e.Env + ": " + e.Reason }

// Validate checks one value against the rule of the setting.
// An empty value passes unless the setting is required.
// Validate is pure and does no input or output.
func Validate(s Setting, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if s.Required {
			return &ValidationError{Env: s.Env, Reason: "a value is required"}
		}
		return nil
	}
	for _, check := range checksFor(s) {
		if reason := check(value); reason != "" {
			return &ValidationError{Env: s.Env, Reason: reason}
		}
	}
	return nil
}

// check reports an empty string when the value passes.
type check func(string) string

// checksFor builds the checks of a setting from its kind and its
// validation sentence.
func checksFor(s Setting) []check {
	var out []check
	if s.Kind == KindInt {
		out = append(out, isWholeNumber)
	}
	if s.Kind == KindEnum && len(s.Choices) > 0 {
		out = append(out, oneOf(s.Choices))
	}
	rule := strings.ToLower(s.Validation)
	if m := rxOneOf.FindStringSubmatch(rule); m != nil {
		out = append(out, oneOf(splitNames(m[1])))
	}
	if m := rxStartsWith.FindStringSubmatch(rule); m != nil {
		out = append(out, hasPrefix(rxScheme.FindAllString(m[1], -1)))
	}
	if m := rxCommaList.FindStringSubmatch(rule); m != nil {
		out = append(out, everyItemIn(splitNames(m[1])))
	}
	if m := rxBetween.FindStringSubmatch(rule); m != nil {
		// A bound that is not a whole number means 0.
		low := anyval.OrZero(strconv.Atoi(m[1]))
		high := anyval.OrZero(strconv.Atoi(m[2]))
		out = append(out, inRange(low, high))
	}
	switch {
	case strings.Contains(rule, "absolute http or https url"):
		out = append(out, isURL([]string{"http", "https"}, false))
	case strings.Contains(rule, "absolute https url"):
		noPath := strings.Contains(rule, "without a path")
		out = append(out, isURL([]string{"https"}, noPath))
	case strings.Contains(rule, "host and port or a url"):
		out = append(out, isHostPortOrURL)
	}
	return out
}

// splitNames turns "etsi and dedi" or "debug, info, warn, error" into a
// list of names.
func splitNames(text string) []string {
	text = strings.ReplaceAll(text, " and ", ", ")
	var out []string
	for _, part := range strings.Split(text, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isWholeNumber(value string) string {
	if _, err := strconv.Atoi(value); err != nil {
		return "the value must be a whole number"
	}
	return ""
}

func oneOf(choices []string) check {
	return func(value string) string {
		for _, c := range choices {
			if value == c {
				return ""
			}
		}
		return "use one of " + strings.Join(choices, ", ")
	}
}

func everyItemIn(choices []string) check {
	inner := oneOf(choices)
	return func(value string) string {
		for _, item := range strings.Split(value, ",") {
			if reason := inner(strings.TrimSpace(item)); reason != "" {
				return reason
			}
		}
		return ""
	}
}

func hasPrefix(prefixes []string) check {
	return func(value string) string {
		for _, p := range prefixes {
			if strings.HasPrefix(value, p) {
				return ""
			}
		}
		return "the value must start with " + strings.Join(prefixes, " or ")
	}
}

func inRange(low, high int) check {
	return func(value string) string {
		n, err := strconv.Atoi(value)
		if err != nil {
			return "the value must be a whole number"
		}
		if n < low || n > high {
			return fmt.Sprintf("the value must be between %d and %d", low, high)
		}
		return ""
	}
}

func isURL(schemes []string, noPath bool) check {
	return func(value string) string {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" {
			return "the value must be an absolute URL"
		}
		ok := false
		for _, s := range schemes {
			if u.Scheme == s {
				ok = true
			}
		}
		if !ok {
			return "the URL scheme must be " + strings.Join(schemes, " or ")
		}
		if noPath && u.Path != "" {
			return "the URL must have no path and no trailing slash"
		}
		return ""
	}
}

func isHostPortOrURL(value string) string {
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" {
			return "the value must be a host and port or a URL"
		}
		return ""
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "the value must be a host and port or a URL"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "the port must be a whole number"
	}
	return ""
}

// ValidateAll checks every setting against the value map, keyed by the
// environment variable name. It returns one error per problem, in the
// order of the settings, so an operator fixes the run in one pass
// (ADR-007 decision 3).
func ValidateAll(settings []Setting, values map[string]string) []error {
	var problems []error
	for _, s := range settings {
		if err := Validate(s, values[s.Env]); err != nil {
			problems = append(problems, err)
		}
	}
	return problems
}
