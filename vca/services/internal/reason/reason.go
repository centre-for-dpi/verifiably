// SPDX-License-Identifier: Apache-2.0

// Package reason turns the refusal of a Connect service into a sentence
// a page may show. The message of a refusal the reader can fix reads as
// a sentence once the Go package prefixes go. Any other error gives no
// sentence, so the page keeps its own plain text and the text of a
// fault inside a service stays off the page.
package reason

import (
	"errors"
	"strings"

	"connectrpc.com/connect"
)

// Of returns the sentence of err when its Connect code is one of codes,
// or "".
func Of(err error, codes ...connect.Code) string {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return ""
	}
	known := false
	for _, c := range codes {
		known = known || cerr.Code() == c
	}
	if !known {
		return ""
	}
	text := strings.TrimSpace(cerr.Message())
	for {
		head, rest, ok := strings.Cut(text, ": ")
		if !ok || !packagePrefix(head) {
			break
		}
		text = strings.TrimSpace(rest)
	}
	if text == "" {
		return ""
	}
	text = strings.ToUpper(text[:1]) + text[1:]
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	return text
}

// packagePrefix reports whether a head of an error text is the name of a
// Go package, such as service or store, which the reader has no use for.
func packagePrefix(head string) bool {
	if head == "" {
		return false
	}
	for _, c := range head {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
