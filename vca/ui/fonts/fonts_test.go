// SPDX-License-Identifier: Apache-2.0

package fonts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const staticFonts = "../static/fonts"

func TestDefaultValidates(t *testing.T) {
	p := Default()
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"font-display": "Big Shoulders Inline Display",
		"font-heading": "Cinzel",
		"font-body":    "Google Sans Flex",
		"font-meta":    "Google Sans Code",
	}
	for _, s := range Slots(p) {
		if s.Role.Family != want[s.Var] {
			t.Errorf("%s = %q, want %q", s.Var, s.Role.Family, want[s.Var])
		}
	}
}

// TestDefaultFilesAreShipped checks that every file exists, is woff2, has an
// OFL licence next to it, and that the pack stays under one megabyte.
func TestDefaultFilesAreShipped(t *testing.T) {
	var total int64
	for _, name := range Files(Default()) {
		st, err := os.Stat(filepath.Join(staticFonts, name))
		if err != nil {
			t.Errorf("font file missing: %v", err)
			continue
		}
		total += st.Size()
		head := make([]byte, 4)
		f, err := os.Open(filepath.Clean(filepath.Join(staticFonts, name)))
		if err != nil {
			t.Fatal(err)
		}
		if _, readErr := f.Read(head); readErr != nil {
			t.Errorf("read %s: %v", name, readErr)
		}
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close %s: %v", name, closeErr)
		}
		if string(head) != "wOF2" {
			t.Errorf("%s is not a woff2 file", name)
		}
	}
	if total > 1<<20 {
		t.Errorf("font pack is %d bytes, want under 1 MiB", total)
	}
	licences, globErr := filepath.Glob(filepath.Join(staticFonts, "LICENSE.*.txt"))
	if globErr != nil {
		t.Fatalf("glob licences: %v", globErr)
	}
	if len(licences) != 4 {
		t.Errorf("want 4 font licence files, got %d", len(licences))
	}
	for _, l := range licences {
		b, err := os.ReadFile(filepath.Clean(l))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "SIL Open Font License, Version 1.1") {
			t.Errorf("%s is not OFL-1.1", l)
		}
	}
}

func TestValidateRejectsBadPacks(t *testing.T) {
	good := Default()
	cases := map[string]func(p *Pack){
		"no name":        func(p *Pack) { p.Name = "" },
		"empty family":   func(p *Pack) { p.Body.Family = "" },
		"quoted family":  func(p *Pack) { p.Body.Family = "x'y" },
		"no fallback":    func(p *Pack) { p.Meta.Fallback = "" },
		"bad file":       func(p *Pack) { p.Display.File = "../etc/passwd" },
		"not woff2":      func(p *Pack) { p.Heading.File = "cinzel.ttf" },
		"no weight":      func(p *Pack) { p.Heading.Weight = "" },
		"uppercase file": func(p *Pack) { p.Heading.File = "Cinzel.woff2" },
	}
	for name, mutate := range cases {
		p := good
		mutate(&p)
		if err := Validate(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestCSS(t *testing.T) {
	p := Default()
	css := CSS(p)
	if strings.Count(css, "@font-face{") != 4 {
		t.Errorf("want 4 @font-face rules, got %d", strings.Count(css, "@font-face{"))
	}
	if strings.Count(css, "font-display:swap") != 4 {
		t.Error("every @font-face must set font-display: swap")
	}
	for _, s := range Slots(p) {
		if !strings.Contains(css, "url(/static/fonts/"+s.Role.File+")") {
			t.Errorf("CSS missing file %s", s.Role.File)
		}
		if !strings.Contains(css, "--"+s.Var+":"+Stack(s.Role)+";") {
			t.Errorf("CSS missing variable %s", s.Var)
		}
		if !strings.Contains(css, "font-weight:"+s.Role.Weight+";") {
			t.Errorf("CSS missing weight for %s", s.Var)
		}
	}
	if Stack(p.Heading) != "'Cinzel', Georgia, 'Times New Roman', serif" {
		t.Errorf("Stack = %q", Stack(p.Heading))
	}
	if len(Files(p)) != 4 {
		t.Errorf("Files = %v", Files(p))
	}
}
