package handlers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// This file covers the small error-handling and formatting paths introduced by
// the lint pass, so the gate's new-code coverage measures tested behaviour
// rather than untested defensive branches.

// ── isRevocationError ────────────────────────────────────────────────────────
//
// The handler layer stays adapter-neutral: it does not import the walt.id
// package, so the contract with the adapters is the surface text of the error,
// probed through errors.As rather than a bare type assertion. The errors.As
// form matters because adapters wrap — a `fmt.Errorf("%w", …)` around the
// revocation error used to defeat the old assertion silently, turning a revoked
// credential into a generic failure toast.

type wrappedErr struct{ inner error }

func (w wrappedErr) Error() string { return "adapter: " + w.inner.Error() }
func (w wrappedErr) Unwrap() error { return w.inner }

func TestIsRevocationError(t *testing.T) {
	revoked := errors.New("credential has been revoked by the issuer")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("connection refused"), false},
		{"direct", revoked, true},
		{"wrapped once", fmt.Errorf("verify: %w", revoked), true},
		{"wrapped in a custom type", wrappedErr{inner: revoked}, true},
		{"wrapped twice", fmt.Errorf("outer: %w", wrappedErr{inner: revoked}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRevocationError(tt.err); got != tt.want {
				t.Errorf("isRevocationError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ── deriveTitleFromPath ──────────────────────────────────────────────────────
//
// The docs TOC falls back to the file path when a markdown file has no H1.
// Title-casing goes through golang.org/x/text/cases because strings.Title is
// deprecated and mishandles Unicode word boundaries — this repo's docs tree
// carries Spanish filenames, so that is not hypothetical.

func TestDeriveTitleFromPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"README.md", "README"},
		{"testdata/bulk-issuance/README.md", "Testdata / Bulk Issuance / README"},
		{"docs/k8s/values-schema.md", "Docs / K8s / Values Schema"},
		{"docs/dpg/inji_certify_preauth.md", "Docs / Dpg / Inji Certify Preauth"},
		{"emisión-federada.md", "Emisión Federada"},
	}
	for _, tt := range tests {
		if got := deriveTitleFromPath(tt.in); got != tt.want {
			t.Errorf("deriveTitleFromPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── scanDocs ─────────────────────────────────────────────────────────────────
//
// The in-app docs browser walks the repo for markdown. The walk is best-effort
// by design: one unreadable directory must not blank the whole TOC, which is
// why the WalkDir callback swallows its error (//nolint:nilerr). This test
// pins that — the readable siblings still have to come back.

func TestScanDocs_SkipsUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0000 directory is still readable")
	}
	root := t.TempDir()

	if err := os.WriteFile(filepath.Join(root, "readable.md"), []byte("# Readable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "hidden.md"), []byte("# Hidden\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore the mode so t.TempDir's cleanup can remove it.
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	entries, err := scanDocs(root)
	if err != nil {
		t.Fatalf("an unreadable subdirectory must not fail the whole scan: %v", err)
	}
	var found bool
	for _, e := range entries {
		if strings.HasSuffix(e.Path, "readable.md") {
			found = true
		}
	}
	if !found {
		t.Errorf("the readable sibling is missing from the TOC: %+v", entries)
	}
}

// Hidden, vendor and node_modules directories are skipped wholesale so the TOC
// is the project's documentation, not its dependencies'.
func TestScanDocs_SkipsVendorAndHiddenDirs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"vendor", "node_modules", ".git", ".hidden"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "doc.md"), []byte("# No\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "keep.md"), []byte("# Keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := scanDocs(root)
	if err != nil {
		t.Fatalf("scanDocs: %v", err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Path, "keep.md") {
		t.Errorf("entries = %+v, want only keep.md", entries)
	}
}

// ── buildJSONSchema ──────────────────────────────────────────────────────────
//
// The JSON Schema the builder emits is what a verifier's presentation
// definition is matched against, so the claim layout per credential format is
// load-bearing. SD-JWT VC puts claims at the top level beside `vct`; W3C VCDM
// nests them under `credentialSubject`. Getting that wrong produces a
// credential that issues fine and can never be presented.

func TestBuildJSONSchema_SDJWTPlacesClaimsAtTopLevel(t *testing.T) {
	out := buildJSONSchema(vctypes.Schema{
		ID:   "Cedula",
		Name: "Cedula",
		Std:  "sd_jwt_vc (IETF)",
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "fullName", Datatype: "string", Required: true},
			{Name: "birthDate", Datatype: "string"},
		},
	})

	for _, want := range []string{`"vct"`, `"iss"`, `"iat"`, `"fullName"`, `"birthDate"`} {
		if !strings.Contains(out, want) {
			t.Errorf("SD-JWT schema is missing %s:\n%s", want, out)
		}
	}
	// The claims must sit beside vct, not nested under credentialSubject.
	if strings.Contains(out, `"credentialSubject"`) {
		t.Errorf("SD-JWT VC must not nest claims under credentialSubject:\n%s", out)
	}
}

func TestBuildJSONSchema_W3CNestsUnderCredentialSubject(t *testing.T) {
	out := buildJSONSchema(vctypes.Schema{
		ID:   "Degree",
		Name: "Degree",
		Std:  "w3c_vcdm_2",
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "degreeName", Datatype: "string", Required: true},
		},
	})

	if !strings.Contains(out, `"credentialSubject"`) {
		t.Errorf("W3C VCDM must nest claims under credentialSubject:\n%s", out)
	}
	if !strings.Contains(out, `"degreeName"`) {
		t.Errorf("claim missing from the W3C schema:\n%s", out)
	}
}
