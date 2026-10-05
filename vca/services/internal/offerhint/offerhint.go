// SPDX-License-Identifier: Apache-2.0

// Package offerhint names the published credential configuration of a
// credential offer, for a stack whose own issuer metadata lists one
// generic entry per wire format. The adapter of such a stack adds the
// configuration id of the schema registry to the offer URI. The wallet
// reads it back and shows the display and the claims that the registry
// publishes for that configuration. The hint never replaces the issuer
// metadata of the stack: the wallet uses it only when the stack entry
// has no display text.
package offerhint

import (
	"net/url"
	"strings"
)

// Param is the query parameter of the offer URI that carries the hint.
// A wallet that does not know it ignores it.
const Param = "vca_configuration"

// Add returns uri with the configuration id as the hint. A blank id, or
// a URI that does not parse, leaves uri as it is. The parameters of the
// offer keep their encoding.
func Add(uri, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return uri
	}
	if _, err := url.Parse(uri); err != nil {
		return uri
	}
	sep := "&"
	if !strings.Contains(uri, "?") {
		sep = "?"
	}
	return uri + sep + Param + "=" + url.QueryEscape(id)
}

// Of returns the configuration id the offer URI names, or the empty
// string.
func Of(uri string) string {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Query().Get(Param))
}
