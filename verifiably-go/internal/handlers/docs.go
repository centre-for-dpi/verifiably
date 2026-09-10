package handlers

// docs.go — in-app documentation browser.
//
// Scans the repo for *.md files and renders:
//   GET /docs             — a table of contents (all markdown, grouped)
//   GET /docs/view?path=… — the selected file, rendered as HTML
//
// path= is validated against the whitelist the TOC built from scanning
// the docs root at startup, so an arbitrary ?path=/etc/passwd is
// rejected — only files the scanner chose to expose are viewable.

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// docsRoot is the filesystem directory to scan for markdown. Set at
// startup via SetDocsRoot; defaults to "." so the handler still works
// in a checked-out repo. In the production container the entrypoint
// sets this to /app/docs-src which the Dockerfile copies from the repo.
var (
	docsMu    sync.RWMutex
	docsRoot  = "."
	docsIndex []docEntry // ordered list of exposed files
)

type docEntry struct {
	Path     string // filesystem path, absolute after SetDocsRoot
	Rel      string // path relative to docsRoot — the "public id"
	Title    string // extracted from the file's first H1, falling back to filename
	Category string // top directory segment, used to group the TOC
}

// SetDocsRoot installs the directory the docs browser scans. Rebuilds
// the index synchronously so /docs serves fresh links immediately.
func SetDocsRoot(root string) error {
	if root == "" {
		return fmt.Errorf("docs root cannot be empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	entries, err := scanDocs(abs)
	if err != nil {
		return err
	}
	docsMu.Lock()
	docsRoot = abs
	docsIndex = entries
	docsMu.Unlock()
	return nil
}

// scanDocs walks root looking for *.md files, skipping vendor/node_modules/
// and hidden dirs. Returns entries sorted by category then relative path
// so the TOC is stable and readable.
func scanDocs(root string) ([]docEntry, error) {
	var out []docEntry
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best-effort; don't fail the whole scan on one bad dir
		}
		name := d.Name()
		if d.IsDir() {
			if name == "node_modules" || name == "vendor" || name == ".git" ||
				strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(name), ".md") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil //nolint:nilerr // an unrelativizable path is skipped, not fatal to the scan
		}
		title := titleFromMarkdown(p)
		if title == "" {
			title = deriveTitleFromPath(rel)
		}
		out = append(out, docEntry{
			Path:     p,
			Rel:      filepath.ToSlash(rel),
			Title:    title,
			Category: categoryFor(rel),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return docCategoryRank(out[i].Category) < docCategoryRank(out[j].Category)
		}
		return out[i].Rel < out[j].Rel
	})
	return out, nil
}

// titleFromMarkdown reads the first #-prefixed line as the doc title.
// Returns "" when the file has no H1, so deriveTitleFromPath can step in.
func titleFromMarkdown(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
		// Stop early — a file without an H1 in the first 30 lines likely
		// doesn't have one at all, no point reading further for title.
	}
	return ""
}

// deriveTitleFromPath is the fallback when the markdown has no H1.
// "testdata/bulk-issuance/README.md" → "Testdata / Bulk Issuance / README".
func deriveTitleFromPath(rel string) string {
	base := strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(filepath.ToSlash(base), "/")
	for i, p := range parts {
		p = strings.ReplaceAll(p, "-", " ")
		p = strings.ReplaceAll(p, "_", " ")
		parts[i] = titleCaser.String(p)
	}
	return strings.Join(parts, " / ")
}

// titleCaser title-cases doc path segments for the generated TOC. cases.Title
// is the Unicode-correct replacement for the deprecated strings.Title.
//
// cases.NoLower is required to preserve strings.Title's behaviour: without it
// cases.Title lowercases the remainder of each word, so an all-caps segment
// like "README" would render as "Readme" in the TOC.
var titleCaser = cases.Title(language.English, cases.NoLower)

// categoryFor picks a group label from the top-level path segment so the
// TOC clusters related docs. "docs/architecture.md" → "Architecture docs",
// "testdata/bulk-issuance/README.md" → "Test data". Everything else → "Root".
func categoryFor(rel string) string {
	rel = filepath.ToSlash(rel)
	switch {
	case strings.HasPrefix(rel, "docs/"):
		return "Architecture & integration"
	case strings.HasPrefix(rel, "testdata/"):
		return "Test data"
	case strings.HasPrefix(rel, "deploy/"):
		return "Deployment"
	default:
		return "Top-level"
	}
}

// docCategoryRank drives the TOC ordering — top-level first, then arch,
// then deploy, then test data. Any other category sinks to the bottom.
func docCategoryRank(cat string) int {
	switch cat {
	case "Top-level":
		return 0
	case "Architecture & integration":
		return 1
	case "Deployment":
		return 2
	case "Test data":
		return 3
	default:
		return 10
	}
}

// lookupDoc finds the entry with matching Rel, or nil. Implicitly rejects
// any ?path= that isn't in our scanned whitelist, so the handler can't be
// used as a path-traversal vehicle.
func lookupDoc(rel string) *docEntry {
	docsMu.RLock()
	defer docsMu.RUnlock()
	for i := range docsIndex {
		if docsIndex[i].Rel == rel {
			return &docsIndex[i]
		}
	}
	return nil
}

// DocsIndex renders the TOC page.
func (h *H) DocsIndex(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	docsMu.RLock()
	entries := append([]docEntry(nil), docsIndex...)
	root := docsRoot
	docsMu.RUnlock()

	// Group by category for template rendering.
	groups := map[string][]docEntry{}
	var order []string
	for _, e := range entries {
		if _, ok := groups[e.Category]; !ok {
			order = append(order, e.Category)
		}
		groups[e.Category] = append(groups[e.Category], e)
	}
	h.render(w, r, "docs_index", h.pageData(sess, map[string]any{
		"Root":   root,
		"Order":  order,
		"Groups": groups,
		"Total":  len(entries),
	}))
}

// docsRenderer is the goldmark pipeline shared across requests. GFM tables
// + fenced code are non-negotiable for our existing READMEs; unsafe HTML
// is NOT enabled so arbitrary <script> in markdown can't leak into the
// rendered page. Process-level singleton, initialised lazily + safely.
var (
	docsRendererOnce sync.Once
	docsRenderer     goldmark.Markdown
)

func markdownRenderer() goldmark.Markdown {
	docsRendererOnce.Do(func() {
		docsRenderer = goldmark.New(
			goldmark.WithExtensions(extension.GFM),
			goldmark.WithRendererOptions(gmhtml.WithHardWraps()),
		)
	})
	return docsRenderer
}

// DocsView renders a single markdown file as HTML.
func (h *H) DocsView(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	rel := strings.TrimSpace(r.URL.Query().Get("path"))
	if rel == "" {
		h.redirect(w, r, "/docs")
		return
	}
	entry := lookupDoc(rel)
	if entry == nil {
		http.NotFound(w, r)
		return
	}
	raw, err := os.ReadFile(entry.Path)
	if err != nil {
		http.Error(w, "read doc: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var buf strings.Builder
	if err := markdownRenderer().Convert(raw, &buf); err != nil {
		http.Error(w, "render markdown: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, r, "docs_view", h.pageData(sess, map[string]any{
		"Entry":     entry,
		"HTML":      template.HTML(buf.String()),
		"AllGroups": nil, // sidebar TOC not needed; TOC page is separate
	}))
}
