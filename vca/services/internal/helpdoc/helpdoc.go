// SPDX-License-Identifier: Apache-2.0

// Package helpdoc renders the documents of a role for the help page of
// its portal (spec: help menu of every role). The documents are the
// Markdown files of vca/docs, embedded in the binary, so the help reads
// the same text as the repository and works offline.
//
// The renderer takes the subset of Markdown the documents use:
// headings, paragraphs, lists, tables, fenced code, inline code, bold
// text and links. It escapes every text. A link to another document of
// the same role opens that document in the portal. A link to a web page
// keeps its http or https address. Any other link becomes plain text, so
// the page never carries a script address or a broken path.
package helpdoc

import (
	"errors"
	"html/template"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/docs"
)

// ErrNotFound reports a document that the role does not list.
var ErrNotFound = errors.New("helpdoc: the role lists no such document")

// Doc is one rendered document.
type Doc struct {
	// Name is the file name without the .md suffix.
	Name string
	// Title is the text of the first heading.
	Title string
	// Body is the document as HTML. Every heading sits one level down,
	// so the page keeps one h1.
	Body template.HTML
}

// Roles maps each role to the documents its help lists, in reading
// order. The glossary closes each list.
func Roles(role string) []string {
	switch role {
	case "admin":
		return []string{"admin", "getting-started", "deploy", "trust-registry", "cli", "glossary"}
	case "issuer":
		return []string{"issuance", "issued-credentials", "schema-registry", "schema-builder-ui", "data-source", "issuer-auth", "glossary"}
	case "holder":
		return []string{"wallet-portal", "wallet-auth", "glossary"}
	case "verifier":
		return []string{
			"verifier-results", "verifier-ingest", "verifier-discovery", "verifier-combined", "verifier-policy", "verifier-auth", "glossary",
		}
	}
	return nil
}

// Listed reports whether the role lists the document.
func Listed(role, name string) bool {
	for _, n := range Roles(role) {
		if n == name {
			return true
		}
	}
	return false
}

// Titles returns the title of each document of a role, in list order.
func Titles(role string) ([]Doc, error) {
	names := Roles(role)
	out := make([]Doc, 0, len(names))
	for _, name := range names {
		raw, err := fs.ReadFile(docs.FS, name+".md")
		if err != nil {
			return nil, err
		}
		out = append(out, Doc{Name: name, Title: titleOf(string(raw), name)})
	}
	return out, nil
}

// Render returns one document of a role. link turns the name of another
// document of the role into the address of its page.
func Render(role, name string, link func(name string) string) (Doc, error) {
	if !Listed(role, name) {
		return Doc{}, ErrNotFound
	}
	raw, err := fs.ReadFile(docs.FS, name+".md")
	if err != nil {
		return Doc{}, err
	}
	r := renderer{role: role, link: link}
	return Doc{Name: name, Title: titleOf(string(raw), name), Body: template.HTML(r.blocks(string(raw)))}, nil //nolint:gosec // every text is escaped
}

// titleOf returns the text of the first heading, or the name.
func titleOf(doc, name string) string {
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return name
}

// renderer turns Markdown into HTML.
type renderer struct {
	role string
	link func(string) string
	out  strings.Builder
}

var (
	headingRe = regexp.MustCompile(`^(#{1,4})\s+(.*)$`)
	bulletRe  = regexp.MustCompile(`^\s*[-*]\s+(.*)$`)
	numberRe  = regexp.MustCompile(`^\s*\d+\.\s+(.*)$`)
	rowRe     = regexp.MustCompile(`^\s*\|.*\|\s*$`)
	ruleRe    = regexp.MustCompile(`^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$`)
	inlineRe  = regexp.MustCompile("`[^`]+`|\\[[^\\]]+\\]\\([^)\\s]+\\)|\\*\\*[^*]+\\*\\*")
)

// blocks renders the block structure of a document.
func (r *renderer) blocks(doc string) string {
	lines := strings.Split(strings.ReplaceAll(doc, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); {
		line := lines[i]
		switch {
		case strings.TrimSpace(line) == "":
			i++
		case strings.HasPrefix(strings.TrimSpace(line), "```"):
			i = r.code(lines, i)
		case headingRe.MatchString(line):
			m := headingRe.FindStringSubmatch(line)
			level := len(m[1]) + 1
			tag := "h" + string(rune('0'+level))
			r.out.WriteString("<" + tag + ">" + r.inline(m[2]) + "</" + tag + ">\n")
			i++
		case rowRe.MatchString(line) && i+1 < len(lines) && ruleRe.MatchString(lines[i+1]):
			i = r.table(lines, i)
		case bulletRe.MatchString(line):
			i = r.list(lines, i, bulletRe, "ul")
		case numberRe.MatchString(line):
			i = r.list(lines, i, numberRe, "ol")
		default:
			i = r.paragraph(lines, i)
		}
	}
	return r.out.String()
}

// code renders a fenced code block and returns the next line.
func (r *renderer) code(lines []string, i int) int {
	var body []string
	for i++; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```"); i++ {
		body = append(body, lines[i])
	}
	r.out.WriteString(`<pre><code>` + template.HTMLEscapeString(strings.Join(body, "\n")) + "</code></pre>\n")
	return i + 1
}

// table renders a pipe table with a header row and returns the next line.
func (r *renderer) table(lines []string, i int) int {
	r.out.WriteString(`<div class="table-wrap"><table><thead><tr>`)
	for _, cell := range cells(lines[i]) {
		r.out.WriteString(`<th scope="col">` + r.inline(cell) + `</th>`)
	}
	r.out.WriteString(`</tr></thead><tbody>`)
	for i += 2; i < len(lines) && rowRe.MatchString(lines[i]); i++ {
		r.out.WriteString(`<tr>`)
		for _, cell := range cells(lines[i]) {
			r.out.WriteString(`<td>` + r.inline(cell) + `</td>`)
		}
		r.out.WriteString(`</tr>`)
	}
	r.out.WriteString("</tbody></table></div>\n")
	return i
}

// cells splits a table row. A pipe inside inline code stays in its cell.
func cells(row string) []string {
	row = strings.TrimSpace(row)
	row = strings.TrimSuffix(strings.TrimPrefix(row, "|"), "|")
	var out []string
	var cur strings.Builder
	code := false
	for _, c := range row {
		switch {
		case c == '`':
			code = !code
			cur.WriteRune(c)
		case c == '|' && !code:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	return append(out, strings.TrimSpace(cur.String()))
}

// list renders a list. An indented line that follows an item continues
// it. It returns the next line.
func (r *renderer) list(lines []string, i int, item *regexp.Regexp, tag string) int {
	r.out.WriteString("<" + tag + ">")
	var cur []string
	flush := func() {
		if cur != nil {
			r.out.WriteString("<li>" + r.inline(strings.Join(cur, " ")) + "</li>")
		}
		cur = nil
	}
	for ; i < len(lines); i++ {
		line := lines[i]
		if m := item.FindStringSubmatch(line); m != nil {
			flush()
			cur = []string{m[1]}
			continue
		}
		if cur != nil && strings.TrimSpace(line) != "" && strings.HasPrefix(line, " ") {
			cur = append(cur, strings.TrimSpace(line))
			continue
		}
		break
	}
	flush()
	r.out.WriteString("</" + tag + ">\n")
	return i
}

// paragraph renders lines up to the next blank line or block.
func (r *renderer) paragraph(lines []string, i int) int {
	var text []string
	for ; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" || headingRe.MatchString(line) || strings.HasPrefix(strings.TrimSpace(line), "```") ||
			bulletRe.MatchString(line) || numberRe.MatchString(line) || rowRe.MatchString(line) {
			break
		}
		text = append(text, strings.TrimSpace(line))
	}
	r.out.WriteString("<p>" + r.inline(strings.Join(text, " ")) + "</p>\n")
	return i
}

// inline renders code spans, links and bold text, and escapes the rest.
func (r *renderer) inline(text string) string {
	var out strings.Builder
	last := 0
	for _, loc := range inlineRe.FindAllStringIndex(text, -1) {
		out.WriteString(template.HTMLEscapeString(text[last:loc[0]]))
		out.WriteString(r.span(text[loc[0]:loc[1]]))
		last = loc[1]
	}
	out.WriteString(template.HTMLEscapeString(text[last:]))
	return out.String()
}

// span renders one inline element.
func (r *renderer) span(s string) string {
	switch {
	case strings.HasPrefix(s, "`"):
		return "<code>" + template.HTMLEscapeString(strings.Trim(s, "`")) + "</code>"
	case strings.HasPrefix(s, "**"):
		return "<strong>" + template.HTMLEscapeString(strings.Trim(s, "*")) + "</strong>"
	}
	sep := strings.Index(s, "](")
	label, target := s[1:sep], s[sep+2:len(s)-1]
	text := r.inline(label)
	href := r.href(target)
	if href == "" {
		return text
	}
	return `<a href="` + template.HTMLEscapeString(href) + `">` + text + `</a>`
}

// href returns the address of a link target, or "" for a target the page
// does not link.
func (r *renderer) href(target string) string {
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return target
	}
	file, _, _ := strings.Cut(target, "#")
	if file == "" {
		return ""
	}
	base := path.Base(file)
	name, ok := strings.CutSuffix(base, ".md")
	if !ok || path.Dir(path.Clean(file)) != "." || !Listed(r.role, name) {
		return ""
	}
	return r.link(name)
}

// Links returns the list of the documents of a role, each a link to its
// page.
func Links(role string, link func(name string) string) (template.HTML, error) {
	docs, err := Titles(role)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString(`<ul class="doc-list">`)
	for _, d := range docs {
		out.WriteString(`<li><a href="` + template.HTMLEscapeString(link(d.Name)) + `">` + template.HTMLEscapeString(d.Title) + `</a></li>`)
	}
	out.WriteString(`</ul>`)
	return template.HTML(out.String()), nil //nolint:gosec // every part is escaped
}

// Article wraps the body of a document for its page.
func Article(d Doc) template.HTML {
	return `<article class="doc">` + d.Body + `</article>`
}
