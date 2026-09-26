// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// version matches a path part that only numbers a version: 1, 1.0, v2.
var version = regexp.MustCompile(`^[vV]?[0-9]+([.][0-9]+)*$`)

// shortForms are the short forms that stay in capitals in a title.
var shortForms = map[string]string{
	"id": "ID", "pid": "PID", "mdl": "mDL", "kyc": "KYC", "vc": "VC", "eu": "EU", "iso": "ISO",
}

// TypeTitle turns a credential type name into a title that reads as
// words in sentence case. OpenBadgeCredential becomes "Open badge
// credential". A URL or URN style type keeps its last part that is not
// a version number. A name that holds a space already reads as words
// and stays as it is, so a display name of the issuer never changes.
// A name with no word in it stays as it is.
func TypeTitle(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsRune(name, ' ') {
		return name
	}
	words := splitWords(lastPart(name))
	if len(words) == 0 {
		return name
	}
	for i, w := range words {
		words[i] = wordCase(w, i == 0)
	}
	return strings.Join(words, " ")
}

// lastPart returns the part of a type name that names the type: the
// fragment or the last path part of a URL, the last part of a URN or a
// dotted name, skipping version numbers. It returns "" when no part is
// left.
func lastPart(name string) string {
	if strings.Contains(name, "://") {
		u, err := url.Parse(name)
		if err != nil {
			return ""
		}
		if u.Fragment != "" {
			return u.Fragment
		}
		name = u.Path
	}
	return lastNamed(strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == ':' }))
}

// lastNamed returns the last part that is not a version number. A dotted
// part, such as a reverse domain name, gives its own last named part.
func lastNamed(parts []string) string {
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if version.MatchString(part) || strings.EqualFold(part, "urn") {
			continue
		}
		if strings.Contains(part, ".") {
			if inner := lastNamed(strings.Split(part, ".")); inner != "" {
				return inner
			}
			continue
		}
		return part
	}
	return ""
}

// splitWords splits a name at underscores, hyphens, and dots, and at
// each change of case: a lower case letter before a capital, or the
// last capital of a run of capitals before a lower case letter. A word
// such as mDL, a small letter before capitals only, stays whole.
func splitWords(name string) []string {
	var words []string
	for _, token := range strings.FieldsFunc(name, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		if shortForm(token) {
			words = append(words, token)
			continue
		}
		runes := []rune(token)
		start := 0
		for i := 1; i < len(runes); i++ {
			if !unicode.IsUpper(runes[i]) {
				continue
			}
			afterLower := unicode.IsLower(runes[i-1])
			endOfRun := unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if afterLower || endOfRun {
				words = append(words, string(runes[start:i]))
				start = i
			}
		}
		words = append(words, string(runes[start:]))
	}
	return words
}

// shortForm reports a token such as mDL or eID: one small letter, then
// capitals only.
func shortForm(token string) bool {
	first, size := utf8.DecodeRuneInString(token)
	rest := token[size:]
	return unicode.IsLower(first) && len(rest) > 1 && strings.ToUpper(rest) == rest && strings.ToLower(rest) != rest
}

// wordCase writes one word of a title. A known short form, a word with
// two capitals or more, or a code such as A1 keeps its capitals. Every
// other word is in lower case, and the first word of the title starts
// with a capital.
func wordCase(word string, first bool) string {
	if short, ok := shortForms[strings.ToLower(word)]; ok {
		return short
	}
	capitals, digits, small := 0, 0, 0
	for _, r := range word {
		switch {
		case unicode.IsUpper(r):
			capitals++
		case unicode.IsDigit(r):
			digits++
		case unicode.IsLower(r):
			small++
		}
	}
	if capitals > 1 || digits > 0 && small == 0 {
		return word
	}
	word = strings.ToLower(word)
	if !first {
		return word
	}
	r, size := utf8.DecodeRuneInString(word)
	return string(unicode.ToUpper(r)) + word[size:]
}
