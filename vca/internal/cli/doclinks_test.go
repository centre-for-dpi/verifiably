// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docLinkRe matches a Markdown link to a Markdown file with an anchor.
var docLinkRe = regexp.MustCompile(`\]\(([^()\s#]*\.md)#([^()\s]+)\)`)

// headingRe matches a Markdown heading.
var headingRe = regexp.MustCompile(`(?m)^#{1,6}\s+(.+?)\s*$`)

// slugOf returns the anchor GitHub gives a heading: lower case, with
// every character but letters, digits, spaces, hyphens, and underscores
// dropped, and each space a hyphen.
func slugOf(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// anchorsOf returns the anchors of the headings of a Markdown file.
func anchorsOf(t *testing.T, path string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, m := range headingRe.FindAllStringSubmatch(readText(t, path), -1) {
		out[slugOf(m[1])] = true
	}
	return out
}

// TestDocLinksToAnchorsResolve: every link from a document to a heading
// of another document names a file that exists and a heading it holds.
// The glossary once linked docs/adr.md for records that live in ADR.md.
func TestDocLinksToAnchorsResolve(t *testing.T) {
	var files []string
	for _, pattern := range []string{"*.md", filepath.Join("adr", "*.md")} {
		found, err := filepath.Glob(filepath.Join(docsDir(), pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, found...)
	}
	files = append(files, filepath.Join("..", "..", "README.md"))
	checked := 0
	for _, file := range files {
		for _, m := range docLinkRe.FindAllStringSubmatch(readText(t, file), -1) {
			target, anchor := filepath.Join(filepath.Dir(file), m[1]), m[2]
			if strings.Contains(m[1], "<") || strings.Contains(anchor, "<") {
				// A template placeholder, such as ADR-<number>.
				continue
			}
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s links to %s, which does not exist", file, m[1])
				continue
			}
			if !anchorsOf(t, target)[anchor] {
				t.Errorf("%s links to %s#%s, which names no heading of that file", file, m[1], anchor)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the documents hold no link to a heading")
	}
}

func TestSlugOfFollowsGitHub(t *testing.T) {
	for heading, want := range map[string]string{
		"ADR-001: Rebrand and redefined purpose": "adr-001-rebrand-and-redefined-purpose",
		"The `vct` of an SD-JWT credential":      "the-vct-of-an-sd-jwt-credential",
		"Claim, scan, paste, accept":             "claim-scan-paste-accept",
	} {
		if got := slugOf(heading); got != want {
			t.Errorf("slugOf(%q) = %q, want %q", heading, got, want)
		}
	}
}
