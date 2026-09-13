// SPDX-License-Identifier: Apache-2.0

// Package retention holds the per schema retention rules
// (ADR-017 decision 5). A rule says how long the log keeps one record of
// a schema. A scheduled job prunes every record whose retention ended.
//
// The package is pure. It parses a setting string and computes the time
// after which a record may go.
package retention

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Errors the package returns.
var (
	// ErrSyntax says a rule is not a "schema=period" pair.
	ErrSyntax = errors.New("retention: a rule must read schema=period")
	// ErrPeriod says a period is not a valid duration.
	ErrPeriod = errors.New("retention: the period is not valid")
	// ErrDuplicate says one schema has two rules.
	ErrDuplicate = errors.New("retention: the schema has two rules")
)

// Day and the longer units the setting accepts. Go durations stop at the
// hour, so the parser adds these three units.
const (
	Day  = 24 * time.Hour
	Week = 7 * Day
	Year = 365 * Day
)

// DefaultKey is the schema name of the rule that covers every schema
// without a rule of its own.
const DefaultKey = "default"

// Policy maps a schema id to a retention period. A zero period means the
// log keeps the record forever.
type Policy struct {
	// Default applies to a schema with no rule of its own.
	Default time.Duration
	// BySchema holds the rule of each named schema.
	BySchema map[string]time.Duration
}

// Parse reads a setting such as "default=5y,diploma=10y,visitor=30d".
// An empty setting returns a policy that keeps every record forever.
// The unit is s, m, h, d, w, or y. A zero period means forever.
func Parse(setting string) (Policy, error) {
	p := Policy{BySchema: map[string]time.Duration{}}
	for _, part := range strings.Split(setting, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, period, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return Policy{}, fmt.Errorf("%w: %q", ErrSyntax, part)
		}
		d, err := ParsePeriod(strings.TrimSpace(period))
		if err != nil {
			return Policy{}, err
		}
		if name == DefaultKey {
			if p.Default != 0 {
				return Policy{}, fmt.Errorf("%w: %s", ErrDuplicate, name)
			}
			p.Default = d
			continue
		}
		if _, dup := p.BySchema[name]; dup {
			return Policy{}, fmt.Errorf("%w: %s", ErrDuplicate, name)
		}
		p.BySchema[name] = d
	}
	return p, nil
}

// ParsePeriod reads one period. It accepts every Go duration unit and
// also d for a day, w for a week, and y for a year of 365 days.
func ParsePeriod(value string) (time.Duration, error) {
	if value == "" {
		return 0, fmt.Errorf("%w: the period is empty", ErrPeriod)
	}
	unit := time.Duration(0)
	switch value[len(value)-1] {
	case 'd':
		unit = Day
	case 'w':
		unit = Week
	case 'y':
		unit = Year
	}
	if unit == 0 {
		d, err := time.ParseDuration(value)
		if err != nil || d < 0 {
			return 0, fmt.Errorf("%w: %q", ErrPeriod, value)
		}
		return d, nil
	}
	n, err := strconv.ParseFloat(value[:len(value)-1], 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: %q", ErrPeriod, value)
	}
	return time.Duration(n * float64(unit)), nil
}

// Period returns the retention period of schemaID.
func (p Policy) Period(schemaID string) time.Duration {
	if d, ok := p.BySchema[schemaID]; ok {
		return d
	}
	return p.Default
}

// RetainUntil returns the time after which the job may prune a record of
// schemaID issued at issuedAt. A zero time means the log keeps it
// forever.
func (p Policy) RetainUntil(schemaID string, issuedAt time.Time) time.Time {
	d := p.Period(schemaID)
	if d <= 0 {
		return time.Time{}
	}
	return issuedAt.Add(d)
}

// Schemas returns the schema names with a rule, sorted.
func (p Policy) Schemas() []string {
	out := make([]string, 0, len(p.BySchema))
	for k := range p.BySchema {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
