// SPDX-License-Identifier: Apache-2.0

package helpdoc

import (
	"errors"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestEveryRoleDocumentRenders renders each document of each role: it
// has a title, keeps the one h1 of the page, and passes the fragment
// rules of the kit.
func TestEveryRoleDocumentRenders(t *testing.T) {
	for _, role := range []string{"admin", "issuer", "holder", "verifier"} {
		titles, err := Titles(role)
		if err != nil || len(titles) < 2 {
			t.Fatalf("%s: titles %v, %v", role, titles, err)
		}
		for _, d := range titles {
			doc, rerr := Render(role, d.Name, func(name string) string { return "/help/doc/" + name })
			if rerr != nil {
				t.Fatalf("%s/%s: %v", role, d.Name, rerr)
			}
			if doc.Title == "" || doc.Title != d.Title || strings.Contains(string(doc.Body), "<h1") || !strings.Contains(string(doc.Body), "<h2>") {
				t.Errorf("%s/%s: title %q, body starts %.200s", role, d.Name, doc.Title, doc.Body)
			}
			a11ytest.AssertFragment(t, string(doc.Body))
		}
	}
}

// TestRenderRefusesWhatTheRoleDoesNotList keeps each portal to the
// documents of its role.
func TestRenderRefusesWhatTheRoleDoesNotList(t *testing.T) {
	if _, err := Render("holder", "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a holder read the admin document: %v", err)
	}
	if Roles("nobody") != nil || Listed("nobody", "glossary") {
		t.Fatal("an unknown role lists documents")
	}
	if got, err := Titles("nobody"); err != nil || len(got) != 0 {
		t.Fatalf("titles of an unknown role: %v, %v", got, err)
	}
	if titleOf("no heading here", "fallback") != "fallback" {
		t.Fatal("a document without a heading has no title")
	}
}

// TestMarkdownSubset renders every element the documents use, escapes
// every text, and links only what is safe.
func TestMarkdownSubset(t *testing.T) {
	doc := strings.Join([]string{
		"# Title <script>",
		"",
		"A paragraph with `code <b>`, **bold**, and a [web page](https://example.org/a?b=1&c=2).",
		"It goes on. See [the wallet](wallet-portal.md#claims), [the admin](admin.md),",
		"[a script](javascript:alert(1)), [a file](../services/x/README.md) and [nothing](#top).",
		"",
		"## Part",
		"",
		"- one item",
		"  that goes on",
		"- two",
		"",
		"1. first",
		"2. second",
		"",
		"| Name | Value |",
		"|---|---|",
		"| `a|b` | c <i> |",
		"",
		"```sh",
		"echo '<x>'",
		"```",
		"#### Deep",
		"Last line.",
	}, "\n")
	r := renderer{role: "holder", link: func(name string) string { return "/wallet/help/doc/" + name }}
	got := r.blocks(doc)
	for _, want := range []string{
		"<h2>Title &lt;script&gt;</h2>", "<code>code &lt;b&gt;</code>", "<strong>bold</strong>",
		`<a href="https://example.org/a?b=1&amp;c=2">web page</a>`,
		`<a href="/wallet/help/doc/wallet-portal">the wallet</a>`, "the admin,", "a script),", "a file and nothing.",
		"<h3>Part</h3>", "<ul><li>one item that goes on</li><li>two</li></ul>", "<ol><li>first</li><li>second</li></ol>",
		`<th scope="col">Name</th>`, "<td><code>a|b</code></td><td>c &lt;i&gt;</td>",
		"<pre><code>echo &#39;&lt;x&gt;&#39;</code></pre>", "<h5>Deep</h5>", "<p>Last line.</p>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the render lacks %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "javascript:") || strings.Contains(got, "<script") || strings.Contains(got, `href="#`) {
		t.Errorf("the render carries an unsafe link\n%s", got)
	}
}

// TestLinksAndArticle lists the documents of a role as links and wraps
// a body for its page.
func TestLinksAndArticle(t *testing.T) {
	list, err := Links("holder", func(name string) string { return "/wallet/help/doc/" + name })
	if err != nil || !strings.Contains(string(list), `<li><a href="/wallet/help/doc/wallet-portal">Wallet portal</a></li>`) {
		t.Fatalf("links = %s, %v", list, err)
	}
	if got := Article(Doc{Body: "<p>x</p>"}); got != `<article class="doc"><p>x</p></article>` {
		t.Fatalf("article = %s", got)
	}
}
