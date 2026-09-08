package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docsFixtureRoot builds a small docs tree:
//
//	README.md                     (H1 "Project overview")
//	docs/architecture.md          (no H1 → title derived from path)
//	deploy/notes.md
//	testdata/bulk-issuance/README.md
//	.hidden/secret.md, node_modules/x.md, vendor/y.md (skipped)
//	notes.txt (not markdown)
func docsFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "intro line\n\n#   Project overview  \n\nbody")
	write("CHANGELOG.md", "# Changelog\n")
	write("docs/architecture.md", "no heading here\n")
	write("deploy/notes.md", "# Deploy notes\n")
	write("testdata/bulk-issuance/README.md", "# Bulk fixtures\n\n| a | b |\n|---|---|\n| 1 | 2 |\n")
	write(".hidden/secret.md", "# hidden\n")
	write("node_modules/x.md", "# nm\n")
	write("vendor/y.md", "# vendor\n")
	write("notes.txt", "# not markdown\n")
	return root
}

// docsInstall points the package-level index at root and restores the
// previous state when the test ends (docsRoot/docsIndex are globals).
func docsInstall(t *testing.T, root string) {
	t.Helper()
	docsMu.RLock()
	prevRoot, prevIndex := docsRoot, docsIndex
	docsMu.RUnlock()
	t.Cleanup(func() {
		docsMu.Lock()
		docsRoot, docsIndex = prevRoot, prevIndex
		docsMu.Unlock()
	})
	if err := SetDocsRoot(root); err != nil {
		t.Fatalf("SetDocsRoot: %v", err)
	}
}

func TestSetDocsRoot(t *testing.T) {
	t.Run("empty root is rejected", func(t *testing.T) {
		if err := SetDocsRoot(""); err == nil || !strings.Contains(err.Error(), "cannot be empty") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("relative root is made absolute and indexed", func(t *testing.T) {
		root := docsFixtureRoot(t)
		docsInstall(t, root) // also registers cleanup
		wd, _ := os.Getwd()
		rel, err := filepath.Rel(wd, root)
		if err != nil {
			t.Fatal(err)
		}
		if err := SetDocsRoot(rel); err != nil {
			t.Fatalf("SetDocsRoot(%q): %v", rel, err)
		}
		docsMu.RLock()
		gotRoot, n := docsRoot, len(docsIndex)
		docsMu.RUnlock()
		if !filepath.IsAbs(gotRoot) || gotRoot != root {
			t.Errorf("docsRoot = %q, want %q", gotRoot, root)
		}
		if n != 5 {
			t.Errorf("indexed %d entries, want 5", n)
		}
	})
	t.Run("unresolvable working directory → Abs error", func(t *testing.T) {
		docsInstall(t, docsFixtureRoot(t)) // snapshot + restore globals
		gone := filepath.Join(t.TempDir(), "gone")
		if err := os.Mkdir(gone, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(gone)
		if err := os.Remove(gone); err != nil {
			t.Fatal(err)
		}
		err := SetDocsRoot("relative-docs")
		if err == nil {
			t.Fatal("expected an error when the cwd no longer exists")
		}
		docsMu.RLock()
		n := len(docsIndex)
		docsMu.RUnlock()
		if n != 5 {
			t.Errorf("failed SetDocsRoot must leave the index untouched, got %d entries", n)
		}
	})
}

func TestScanDocs(t *testing.T) {
	root := docsFixtureRoot(t)
	entries, err := scanDocs(root)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, e := range entries {
		rels = append(rels, e.Rel)
	}
	// Same category sorts by relative path (CHANGELOG before README).
	want := []string{"CHANGELOG.md", "README.md", "docs/architecture.md", "deploy/notes.md", "testdata/bulk-issuance/README.md"}
	if strings.Join(rels, ",") != strings.Join(want, ",") {
		t.Fatalf("order/filter wrong: got %v want %v", rels, want)
	}
	if entries[1].Title != "Project overview" || entries[1].Category != "Top-level" {
		t.Errorf("README entry = %+v", entries[1])
	}
	if entries[2].Title != "Docs / Architecture" || entries[2].Category != "Architecture & integration" {
		t.Errorf("architecture entry = %+v", entries[2])
	}
	if entries[3].Category != "Deployment" || entries[4].Category != "Test data" {
		t.Errorf("categories: %+v / %+v", entries[3], entries[4])
	}
	if entries[4].Path != filepath.Join(root, "testdata", "bulk-issuance", "README.md") {
		t.Errorf("Path = %q", entries[4].Path)
	}

	t.Run("unreadable subdirectory is skipped, not fatal", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Fatal("this test needs a non-root user (root ignores directory permissions)")
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "a.md"), []byte("# A\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		locked := filepath.Join(root, "locked")
		if err := os.Mkdir(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		entries, err := scanDocs(root)
		if err != nil {
			t.Fatalf("scanDocs: %v", err)
		}
		if len(entries) != 1 || entries[0].Rel != "a.md" {
			t.Errorf("entries = %+v", entries)
		}
	})
	t.Run("missing root yields no entries and no error", func(t *testing.T) {
		entries, err := scanDocs(filepath.Join(t.TempDir(), "nope"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("got %v, %v", entries, err)
		}
	})
}

func TestTitleFromMarkdown(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.md")
	if err := os.WriteFile(p, []byte("text\n## not h1\n# Real Title\n# second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := titleFromMarkdown(p); got != "Real Title" {
		t.Errorf("got %q", got)
	}
	if err := os.WriteFile(p, []byte("no heading\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := titleFromMarkdown(p); got != "" {
		t.Errorf("no-H1 file: got %q", got)
	}
	if got := titleFromMarkdown(filepath.Join(dir, "missing.md")); got != "" {
		t.Errorf("missing file: got %q", got)
	}
}

func TestDeriveTitleFromPath(t *testing.T) {
	cases := map[string]string{
		"testdata/bulk-issuance/README.md": "Testdata / Bulk Issuance / README",
		"docs/my_file-name.md":             "Docs / My File Name",
		"README.md":                        "README",
	}
	for in, want := range cases {
		if got := deriveTitleFromPath(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestCategoryForAndRank(t *testing.T) {
	cases := []struct {
		rel, cat string
		rank     int
	}{
		{"docs/a.md", "Architecture & integration", 1},
		{"testdata/x/README.md", "Test data", 3},
		{"deploy/k8s.md", "Deployment", 2},
		{"README.md", "Top-level", 0},
	}
	for _, c := range cases {
		if got := categoryFor(c.rel); got != c.cat {
			t.Errorf("categoryFor(%q) = %q", c.rel, got)
		}
		if got := docCategoryRank(c.cat); got != c.rank {
			t.Errorf("docCategoryRank(%q) = %d", c.cat, got)
		}
	}
	if got := docCategoryRank("Something else"); got != 10 {
		t.Errorf("unknown category rank = %d", got)
	}
}

func TestLookupDoc(t *testing.T) {
	docsInstall(t, docsFixtureRoot(t))
	if e := lookupDoc("docs/architecture.md"); e == nil || e.Title != "Docs / Architecture" {
		t.Errorf("lookup = %+v", e)
	}
	if e := lookupDoc("../../etc/passwd"); e != nil {
		t.Errorf("traversal path must not resolve, got %+v", e)
	}
	if e := lookupDoc("notes.txt"); e != nil {
		t.Errorf("non-markdown must not resolve, got %+v", e)
	}
}

func docsNewH(t *testing.T) *H {
	t.Helper()
	return &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "docs_index", "docs_view")}
}

func TestDocsIndex(t *testing.T) {
	root := docsFixtureRoot(t)
	docsInstall(t, root)
	h := docsNewH(t)

	rr := httptest.NewRecorder()
	h.DocsIndex(rr, htmxMainRequest(http.MethodGet, "/docs"))
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	for _, want := range []string{root, "5 documents indexed", "Top-level", "Architecture &amp; integration", "Deployment", "Test data",
		`href="/docs/view?path=docs%2farchitecture.md"`, "Project overview", "Bulk fixtures"} {
		if !strings.Contains(body, want) {
			t.Errorf("index missing %q", want)
		}
	}
	// Category order is Top-level → Architecture → Deployment → Test data.
	if strings.Index(body, "Top-level") > strings.Index(body, "Architecture &amp; integration") ||
		strings.Index(body, "Deployment") > strings.Index(body, "Test data") {
		t.Error("categories out of order")
	}
	if strings.Contains(body, "secret.md") || strings.Contains(body, "notes.txt") {
		t.Error("hidden / non-markdown files leaked into the TOC")
	}

	t.Run("empty root renders the empty state", func(t *testing.T) {
		docsInstall(t, t.TempDir())
		rr := httptest.NewRecorder()
		h.DocsIndex(rr, httptest.NewRequest(http.MethodGet, "/docs", nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "No markdown files were found") || !strings.Contains(rr.Body.String(), "<html") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
}

func TestMarkdownRenderer(t *testing.T) {
	a, b := markdownRenderer(), markdownRenderer()
	if a == nil || a != b {
		t.Fatal("markdownRenderer must return one shared instance")
	}
	var sb strings.Builder
	if err := a.Convert([]byte("| a |\n|---|\n| 1 |\n\n<script>x()</script>"), &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "<table>") {
		t.Errorf("GFM tables not enabled: %q", out)
	}
	if strings.Contains(out, "<script>") {
		t.Errorf("raw HTML must be escaped: %q", out)
	}
}

func TestDocsView(t *testing.T) {
	root := docsFixtureRoot(t)
	docsInstall(t, root)
	h := docsNewH(t)

	t.Run("no path → redirect to /docs", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.DocsView(rr, httptest.NewRequest(http.MethodGet, "/docs/view?path=+", nil))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/docs" {
			t.Fatalf("got %d Location=%q", rr.Code, rr.Header().Get("Location"))
		}
		rr = httptest.NewRecorder()
		h.DocsView(rr, htmxMainRequest(http.MethodGet, "/docs/view"))
		if rr.Code != http.StatusOK || rr.Header().Get("HX-Redirect") != "/docs" {
			t.Fatalf("htmx: got %d HX-Redirect=%q", rr.Code, rr.Header().Get("HX-Redirect"))
		}
	})
	t.Run("unknown / traversal path → 404", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.DocsView(rr, httptest.NewRequest(http.MethodGet, "/docs/view?path=../../etc/passwd", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("renders markdown as HTML", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.DocsView(rr, htmxMainRequest(http.MethodGet, "/docs/view?path=testdata/bulk-issuance/README.md"))
		body := rr.Body.String()
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		for _, want := range []string{"Docs · Test data", "<h1>Bulk fixtures</h1>", "<table>", "testdata/bulk-issuance/README.md"} {
			if !strings.Contains(body, want) {
				t.Errorf("view missing %q in %q", want, body)
			}
		}
	})
	t.Run("indexed file deleted afterwards → 500", func(t *testing.T) {
		if err := os.Remove(filepath.Join(root, "deploy", "notes.md")); err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		h.DocsView(rr, httptest.NewRequest(http.MethodGet, "/docs/view?path=deploy/notes.md", nil))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "read doc:") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
}
