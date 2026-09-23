// SPDX-License-Identifier: Apache-2.0

package msg

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	dashRE        = regexp.MustCompile("[–—]")
	wordRE        = regexp.MustCompile(`[A-Za-z][A-Za-z'-]*`)
	placeholderRE = regexp.MustCompile(`\{(\d+)\}`)
	beForms       = map[string]bool{"is": true, "are": true, "was": true, "were": true, "be": true, "been": true, "being": true}
)

// bannedRules reads hack/ste-words.txt: one "<phrase> -> <replacement>"
// per line. Each phrase matches on word boundaries, in any case.
func bannedRules(t *testing.T) map[string]*regexp.Regexp {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "hack", "ste-words.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read only
	rules := map[string]*regexp.Regexp{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "->") {
			continue
		}
		bad := strings.TrimSpace(strings.SplitN(line, "->", 2)[0])
		pattern := `(?i)(^|[^\w-])` + strings.ReplaceAll(regexp.QuoteMeta(bad), `\ `, `\s+`)
		if last := bad[len(bad)-1]; ('a' <= last && last <= 'z') || ('0' <= last && last <= '9') {
			pattern += `([^\w-]|$)`
		}
		rules[bad] = regexp.MustCompile(pattern)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rules) < 50 {
		t.Fatalf("read only %d banned words", len(rules))
	}
	return rules
}

// sentences splits a value at every full stop, question mark and colon.
func sentences(v string) []string {
	var out []string
	start := 0
	for i, r := range v {
		if r == '.' || r == '?' || r == ':' {
			if s := strings.TrimSpace(v[start:i]); s != "" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	if s := strings.TrimSpace(v[start:]); s != "" {
		out = append(out, s)
	}
	return out
}

// TestEveryKeyHasASentence checks every English value against the STE
// rules of the pages: sentences of 20 words or fewer, terminal
// punctuation unless the key is a short label, no dashes, no banned
// word, no passive voice, and placeholders numbered from 1 without gaps.
func TestEveryKeyHasASentence(t *testing.T) {
	rules := bannedRules(t)
	keys := Keys()
	if len(keys) < 100 {
		t.Fatalf("catalogue has %d keys, want at least 100", len(keys))
	}
	if !sort.StringsAreSorted(keys) {
		t.Error("Keys() must be sorted")
	}
	for _, key := range keys {
		v, ok := Lookup(key)
		if !ok || strings.TrimSpace(v) == "" || v != strings.TrimSpace(v) {
			t.Errorf("%s: empty value or stray space: %q", key, v)
			continue
		}
		if dashRE.MatchString(v) {
			t.Errorf("%s: holds an en or em dash", key)
		}
		words := strings.Fields(v)
		if strings.HasSuffix(key, ".label") {
			if len(words) > 4 {
				t.Errorf("%s: a label has at most 4 words, got %d", key, len(words))
			}
			if strings.HasSuffix(v, ".") {
				t.Errorf("%s: a label ends without a full stop", key)
			}
		} else if !strings.HasSuffix(v, ".") && !strings.HasSuffix(v, "?") && !strings.HasSuffix(v, ":") {
			t.Errorf("%s: must end with . ? or : %q", key, v)
		}
		for _, s := range sentences(v) {
			if n := len(strings.Fields(s)); n > 20 {
				t.Errorf("%s: sentence of %d words: %q", key, n, s)
			}
		}
		for bad, rx := range rules {
			if rx.MatchString(v) {
				t.Errorf("%s: banned word %q in %q", key, bad, v)
			}
		}
		ws := wordRE.FindAllString(v, -1)
		for i := 0; i+1 < len(ws); i++ {
			if beForms[strings.ToLower(ws[i])] && isParticiple(ws[i+1]) {
				t.Errorf("%s: passive %q %q in %q", key, ws[i], ws[i+1], v)
			}
		}
		seen := map[string]bool{}
		for _, m := range placeholderRE.FindAllStringSubmatch(v, -1) {
			seen[m[1]] = true
		}
		for i := 1; i <= len(seen); i++ {
			if !seen[string(rune('0'+i))] {
				t.Errorf("%s: placeholders must run from {1} without gaps: %q", key, v)
			}
		}
	}
}

// irregular lists past participles that do not end in "ed".
var irregular = map[string]bool{
	"built": true, "done": true, "found": true, "given": true, "held": true, "hidden": true, "kept": true,
	"known": true, "left": true, "lost": true, "made": true, "met": true, "paid": true, "put": true,
	"read": true, "run": true, "seen": true, "sent": true, "set": true, "shown": true, "sold": true,
	"taken": true, "told": true, "thought": true, "understood": true, "written": true,
}

func isParticiple(w string) bool {
	w = strings.ToLower(w)
	if irregular[w] {
		return true
	}
	if w == "need" || w == "indeed" || w == "red" || w == "embed" || w == "unused" {
		return false
	}
	return len(w) >= 4 && strings.HasSuffix(w, "ed")
}

func TestTSubstitutes(t *testing.T) {
	cases := []struct {
		key  string
		args []string
		want string
	}{
		{"intro.signin.text", []string{"issuers", "vca-issuer-realm"}, "This deployment signs issuers in through vca-issuer-realm. You can register if you have no account."},
		{"roles.available_on.label", []string{"walt.id, Inji"}, "Available on walt.id, Inji"},
		{"roles.available_on.label", nil, "Available on {1}"},
		{"shell.sign_out.label", []string{"extra"}, "Sign out"},
		{"no.such.key", []string{"x"}, "no.such.key"},
	}
	for _, c := range cases {
		if got := T(c.key, c.args...); got != c.want {
			t.Errorf("T(%q, %v) = %q, want %q", c.key, c.args, got, c.want)
		}
	}
	if _, ok := Lookup("no.such.key"); ok {
		t.Error("Lookup of an unknown key must report false")
	}
	// {2} then {1}: the order of the arguments follows the numbers, not the text.
	if got := substitute("{2} before {1}.", []string{"a", "b"}); got != "b before a." {
		t.Errorf("substitute = %q", got)
	}
}

// TestKeysAreWellFormed checks the naming: lower case segments joined by
// dots, with underscores inside a segment.
func TestKeysAreWellFormed(t *testing.T) {
	keyRE := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9][a-z0-9_]*)+$`)
	for _, k := range Keys() {
		if !keyRE.MatchString(k) {
			t.Errorf("key %q is not well formed", k)
		}
	}
	for _, prefix := range []string{"layout.", "shell.", "common.", "role.", "landing.", "roles.", "intro.", "admin.", "issuer.", "holder.", "verifier."} {
		found := false
		for _, k := range Keys() {
			if strings.HasPrefix(k, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no key with prefix %q", prefix)
		}
	}
}
