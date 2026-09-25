// SPDX-License-Identifier: Apache-2.0

// Package msg is the message catalogue of the VCA pages. Every sentence a
// page shows is a key here, so one place holds the words, the STE test
// checks them, and a translation can replace them.
//
// Keys are dotted paths in lower case: the page or area, the element, and
// the part. A key that ends in ".label" is a short label of at most four
// words with no full stop. Every other value is one or more sentences that
// end in a full stop, a question mark or a colon. A value can hold the
// placeholders {1}, {2} and so on, which T fills from its arguments.
package msg

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// T returns the English text of key with the placeholders {1}, {2} and so
// on replaced by args in order. A placeholder without an argument stays in
// the text. An unknown key returns the key itself, so a missing sentence
// shows on the page and in a test instead of an empty string.
func T(key string, args ...string) string {
	v, ok := en[key]
	if !ok {
		return key
	}
	return substitute(v, args)
}

// Lookup returns the English text of key and whether the key exists.
func Lookup(key string) (string, bool) {
	v, ok := en[key]
	return v, ok
}

// Keys returns every key of the catalogue in sorted order.
func Keys() []string {
	keys := make([]string, 0, len(en))
	for k := range en {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// substitute replaces {n} with args[n-1] for every argument given.
func substitute(v string, args []string) string {
	if len(args) == 0 || !strings.Contains(v, "{") {
		return v
	}
	pairs := make([]string, 0, 2*len(args))
	for i, a := range args {
		pairs = append(pairs, "{"+strconv.Itoa(i+1)+"}", a)
	}
	return strings.NewReplacer(pairs...).Replace(v)
}

// Age names a duration in its largest whole unit: minutes under an
// hour, hours under two days, then days. A negative age reads as zero.
func Age(d time.Duration) string {
	switch {
	case d < time.Hour:
		return T("verifier.age.minutes.label", strconv.Itoa(int(max(d, 0)/time.Minute)))
	case d < 48*time.Hour:
		return T("verifier.age.hours.label", strconv.Itoa(int(d/time.Hour)))
	}
	return T("verifier.age.days.label", strconv.Itoa(int(d/(24*time.Hour))))
}
