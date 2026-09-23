// SPDX-License-Identifier: Apache-2.0

package fonts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const staticFonts = "../static/fonts"

func TestDefaultValidates(t *testing.T) {
	p := Default()
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
	slots := Slots(p)
	wantVars := []string{"font-heading", "font-body", "font-mono"}
	if len(slots) != len(wantVars) {
		t.Fatalf("got %d slots, want %d", len(slots), len(wantVars))
	}
	for i, s := range slots {
		if s.Var != wantVars[i] {
			t.Errorf("slot %d = %q, want %q", i, s.Var, wantVars[i])
		}
	}
	if slots[0].Role.Family != "Cinzel" {
		t.Errorf("font-heading = %q, want Cinzel", slots[0].Role.Family)
	}
	if slots[1].Role.Family != "Google Sans Flex" {
		t.Errorf("font-body = %q, want Google Sans Flex", slots[1].Role.Family)
	}
	mono := slots[2].Role
	if mono.Family != "" || mono.File != "" {
		t.Errorf("font-mono = %+v, want a generic stack with no family and no file", mono)
	}
	if !strings.HasSuffix(mono.Fallback, "monospace") {
		t.Errorf("font-mono fallback %q does not end in monospace", mono.Fallback)
	}
}

// TestDefaultFilesAreShipped checks that the pack needs exactly two files,
// that each is woff2 with an OFL licence next to it, and that the pack
// stays under one megabyte.
func TestDefaultFilesAreShipped(t *testing.T) {
	files := Files(Default())
	if len(files) != 2 {
		t.Fatalf("Files = %v, want two files", files)
	}
	var total int64
	for _, name := range files {
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
	woff2, globErr := filepath.Glob(filepath.Join(staticFonts, "*.woff2"))
	if globErr != nil {
		t.Fatalf("glob fonts: %v", globErr)
	}
	if len(woff2) != 2 {
		t.Errorf("want 2 woff2 files in static/fonts, got %v", woff2)
	}
	licences, globErr := filepath.Glob(filepath.Join(staticFonts, "LICENSE.*.txt"))
	if globErr != nil {
		t.Fatalf("glob licences: %v", globErr)
	}
	if len(licences) != 2 {
		t.Errorf("want 2 font licence files, got %v", licences)
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

func TestShipped(t *testing.T) {
	got := Shipped()
	if len(got) != 2 {
		t.Fatalf("Shipped has %d families, want 2", len(got))
	}
	for _, family := range []string{"Cinzel", "Google Sans Flex"} {
		r, ok := got[family]
		if !ok {
			t.Errorf("Shipped has no %q", family)
			continue
		}
		if r.Family != family || r.File == "" || r.Weight == "" || r.Fallback == "" {
			t.Errorf("Shipped[%q] = %+v", family, r)
		}
		if _, err := os.Stat(filepath.Join(staticFonts, r.File)); err != nil {
			t.Errorf("Shipped[%q]: %v", family, err)
		}
	}
	got["Cinzel"] = Role{}
	if Shipped()["Cinzel"].File == "" {
		t.Error("Shipped returns shared state")
	}
}

func TestValidateRejectsBadPacks(t *testing.T) {
	good := Default()
	cases := map[string]func(p *Pack){
		"no name":             func(p *Pack) { p.Name = "" },
		"empty family":        func(p *Pack) { p.Body.Family = "" },
		"quoted family":       func(p *Pack) { p.Body.Family = "x'y" },
		"no fallback":         func(p *Pack) { p.Body.Fallback = "" },
		"fallback breaks css": func(p *Pack) { p.Body.Fallback = "serif;}body{color:red" },
		"bad file":            func(p *Pack) { p.Body.File = "../etc/passwd" },
		"not woff2":           func(p *Pack) { p.Heading.File = "cinzel.ttf" },
		"heading no file":     func(p *Pack) { p.Heading.File = "" },
		"no weight":           func(p *Pack) { p.Heading.Weight = "" },
		"uppercase file":      func(p *Pack) { p.Heading.File = "Cinzel.woff2" },
		"mono with a file":    func(p *Pack) { p.Mono.File = "mono.woff2" },
		"mono with a family":  func(p *Pack) { p.Mono.Family = "Some Mono" },
		"mono with a weight":  func(p *Pack) { p.Mono.Weight = "400" },
		"mono not monospace":  func(p *Pack) { p.Mono.Fallback = "Georgia, serif" },
		"mono no fallback":    func(p *Pack) { p.Mono.Fallback = "" },
	}
	for name, mutate := range cases {
		p := good
		mutate(&p)
		if err := Validate(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

var monoVar = regexp.MustCompile(`--font-mono:([^;]*);`)

func TestCSS(t *testing.T) {
	p := Default()
	css := CSS(p)
	if n := strings.Count(css, "@font-face{"); n != 2 {
		t.Errorf("want 2 @font-face rules, got %d", n)
	}
	if strings.Count(css, "font-display:swap") != 2 {
		t.Error("every @font-face must set font-display: swap")
	}
	for _, s := range Slots(p) {
		if !strings.Contains(css, "--"+s.Var+":"+Stack(s.Role)+";") {
			t.Errorf("CSS missing variable %s", s.Var)
		}
		if s.Role.File == "" {
			continue
		}
		if !strings.Contains(css, "url(/static/fonts/"+s.Role.File+")") {
			t.Errorf("CSS missing file %s", s.Role.File)
		}
		if !strings.Contains(css, "font-weight:"+s.Role.Weight+";") {
			t.Errorf("CSS missing weight for %s", s.Var)
		}
	}
	m := monoVar.FindStringSubmatch(css)
	if m == nil {
		t.Fatal("CSS has no --font-mono variable")
	}
	if strings.ContainsAny(m[1], `'"`) {
		t.Errorf("--font-mono holds a quoted family: %q", m[1])
	}
	if !strings.HasSuffix(m[1], "monospace") {
		t.Errorf("--font-mono = %q, want a stack that ends in monospace", m[1])
	}
	if Stack(p.Heading) != "'Cinzel', Georgia, 'Times New Roman', serif" {
		t.Errorf("Stack = %q", Stack(p.Heading))
	}
	if Stack(p.Mono) != p.Mono.Fallback {
		t.Errorf("Stack(mono) = %q, want the fallback alone", Stack(p.Mono))
	}
}
