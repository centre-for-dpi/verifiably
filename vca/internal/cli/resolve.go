// SPDX-License-Identifier: Apache-2.0

package cli

import "strings"

// Origin says where a resolved value came from.
type Origin int

const (
	// OriginNone means no source held a value.
	OriginNone Origin = iota
	// OriginFlag means a command line flag held the value.
	OriginFlag
	// OriginEnv means the process environment held the value.
	OriginEnv
	// OriginFile means the file of the --env-file flag held the value.
	OriginFile
	// OriginAnswer means the operator typed the value.
	OriginAnswer
	// OriginDomain means the base domain of the run derived the value
	// (ADR-007 decision 2).
	OriginDomain
	// OriginExisting means an earlier run of setup generated the secret.
	// The CLI keeps it so a second run does not lose a secret
	// (ADR-007 decision 5).
	OriginExisting
	// OriginDefault means the proto default supplied the value.
	OriginDefault
)

// String names the origin for the summary table.
func (o Origin) String() string {
	switch o {
	case OriginFlag:
		return "flag"
	case OriginEnv:
		return "environment"
	case OriginFile:
		return "env file"
	case OriginAnswer:
		return "answer"
	case OriginDomain:
		return "domain"
	case OriginExisting:
		return "existing file"
	case OriginDefault:
		return "default"
	default:
		return "missing"
	}
}

// Sources holds every place a value can come from, keyed by the
// environment variable name of the setting.
type Sources struct {
	// Flags holds the values of --set flags.
	Flags map[string]string
	// Env reads the process environment. A nil function reads nothing.
	Env func(string) string
	// File holds the values of the --env-file file.
	File map[string]string
	// Answers holds the values the operator typed.
	Answers map[string]string
	// Existing holds the values an earlier run of setup wrote.
	// The CLI reads it only for a secret setting.
	Existing map[string]string
}

// Resolve returns the value of one setting and the source it came from.
// The order is the order of ADR-007 decision 4, highest first:
// CLI flag, process environment, env file, interactive answer, default.
func Resolve(s Setting, src Sources) (string, Origin) {
	if v, ok := lookup(src.Flags, s.Env); ok {
		return v, OriginFlag
	}
	if src.Env != nil {
		if v := strings.TrimSpace(src.Env(s.Env)); v != "" {
			return v, OriginEnv
		}
	}
	if v, ok := lookup(src.File, s.Env); ok {
		return v, OriginFile
	}
	if v, ok := lookup(src.Answers, s.Env); ok {
		return v, OriginAnswer
	}
	if s.Secret {
		if v, ok := lookup(src.Existing, s.Env); ok {
			return v, OriginExisting
		}
	}
	if s.Default != "" {
		return s.Default, OriginDefault
	}
	return "", OriginNone
}

func lookup(m map[string]string, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	if v = strings.TrimSpace(v); v == "" {
		return "", false
	}
	return v, true
}

// Resolution is one setting with the value and the origin the CLI chose.
type Resolution struct {
	Setting Setting
	Value   string
	Origin  Origin
}

// ResolveAll resolves every setting in order.
func ResolveAll(settings []Setting, src Sources) []Resolution {
	out := make([]Resolution, 0, len(settings))
	for _, s := range settings {
		v, o := Resolve(s, src)
		out = append(out, Resolution{Setting: s, Value: v, Origin: o})
	}
	return out
}

// Values turns resolutions into a map keyed by environment variable name.
func Values(list []Resolution) map[string]string {
	out := make(map[string]string, len(list))
	for _, r := range list {
		if r.Value != "" {
			out[r.Setting.Env] = r.Value
		}
	}
	return out
}

// Missing lists the required settings that no source filled.
// The non interactive run fails and names every one of them
// (ADR-007 decision 3).
func Missing(list []Resolution) []Setting {
	var out []Setting
	for _, r := range list {
		if r.Setting.Required && r.Value == "" {
			out = append(out, r.Setting)
		}
	}
	return out
}
