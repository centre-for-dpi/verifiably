// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"slices"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
)

// FixedClaims returns the display claims that every presentation of a
// credential carries, whatever the holder ticks, in name order. An
// SD-JWT carries the claims of its payload that no disclosure hides. A
// credential with no selective disclosure carries each claim. A
// consent screen lists these claims, so consent equals disclosure.
func FixedClaims(raw []byte) ([]string, error) {
	if DetectFormat(raw) == FormatSDJWT {
		p, err := sdjwt.Parse(string(raw))
		if err != nil {
			return nil, err
		}
		payload, err := jose.PeekPayload(p.IssuerJWT)
		if err != nil {
			return nil, err
		}
		var out []string
		for k := range payload {
			if !reserved[k] {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return out, nil
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(c.Claims))
	for k := range c.Claims {
		out = append(out, k)
	}
	slices.Sort(out)
	return out, nil
}
