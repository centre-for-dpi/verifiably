// SPDX-License-Identifier: Apache-2.0

package pex

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
)

// ParseJSONPath reads the plain JSONPath forms a presentation definition
// uses: $.a.b, $['a']["b"], $.a[0], and $.a[*]. It refuses a
// recursive descent, a filter, a slice, and a union, because a DCQL
// claims path cannot hold them.
func ParseJSONPath(text string) (dcql.Path, error) {
	if !strings.HasPrefix(text, "$") {
		return nil, fmt.Errorf("pex: the JSONPath %q does not start at the root $", text)
	}
	var out dcql.Path
	rest := text[1:]
	for rest != "" {
		switch rest[0] {
		case '.':
			rest = rest[1:]
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			name := rest[:end]
			if name == "" || name == "*" {
				return nil, fmt.Errorf("pex: the JSONPath %q has a step that DCQL cannot hold", text)
			}
			out = append(out, dcql.Name(name))
			rest = rest[end:]
		case '[':
			seg, n, err := bracket(rest)
			if err != nil {
				return nil, fmt.Errorf("pex: the JSONPath %q: %w", text, err)
			}
			out = append(out, seg)
			rest = rest[n:]
		default:
			return nil, fmt.Errorf("pex: the JSONPath %q is not valid after the root", text)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pex: the JSONPath %q selects the whole credential", text)
	}
	return out, nil
}

// bracket reads one bracket step at the start of text and returns the
// segment and the length of the step.
func bracket(text string) (dcql.Segment, int, error) {
	if len(text) > 1 && (text[1] == '\'' || text[1] == '"') {
		quote := text[1]
		end := strings.IndexByte(text[2:], quote)
		if end < 0 || len(text) < end+4 || text[end+3] != ']' {
			return dcql.Segment{}, 0, fmt.Errorf("a quoted name has no end")
		}
		return dcql.Name(text[2 : end+2]), end + 4, nil
	}
	end := strings.IndexByte(text, ']')
	if end < 0 {
		return dcql.Segment{}, 0, fmt.Errorf("a bracket has no end")
	}
	inner := text[1:end]
	if inner == "*" {
		return dcql.All(), end + 1, nil
	}
	i, err := strconv.Atoi(inner)
	if err != nil || i < 0 {
		return dcql.Segment{}, 0, fmt.Errorf("the step [%s] is not a name, a position, or *", inner)
	}
	return dcql.Index(i), end + 1, nil
}
