package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// nopTranslator satisfies handlers.Translator for a parse-only check.
type nopTranslator struct{}

func (nopTranslator) Translate(_ context.Context, text, _ string) string { return text }

// Every template must parse.
//
// A malformed action — an {{if}} without its {{end}}, a typo'd field — is not a
// compile error and no unit test renders most pages, so it surfaces only when
// loadTemplates runs at startup and takes the whole server down. This is the
// cheapest possible guard: parse the real tree the way main() does.
func TestTemplatesParse(t *testing.T) {
	if _, err := loadTemplates("../../templates", nopTranslator{}); err != nil {
		t.Fatalf("templates must parse or the server cannot boot: %v", err)
	}
}

// The issue form's Validity window is gated on the schema declaring an expiry.
//
// Shown unconditionally it is a trap: the adapters only write temporal claims
// into a template that declares them, so on a non-expiring schema the operator
// fills in dates that are silently dropped — the same silent-drop that let
// every Inji Certify credential never expire.
func TestIssueFormGatesValidityWindowOnSchemaExpiry(t *testing.T) {
	// Asserted against the template SOURCE. TestTemplatesParse already proves
	// the tree is well-formed; what matters here is that the gate is present,
	// and the source says that plainly.
	b, err := os.ReadFile("../../templates/pages/issuer_issue.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	if !strings.Contains(src, ".Schema.ExpiresWithWindow") {
		t.Error("the Validity window section must be gated on .Schema.ExpiresWithWindow — " +
			"otherwise it renders for schemas whose window would be silently dropped")
	}
	// The internal markers must never be rendered as inputs; the operator sets
	// the window through these datetime pickers.
	for _, want := range []string{`name="valid_from"`, `name="valid_until"`} {
		if !strings.Contains(src, want) {
			t.Errorf("the issue form must keep its %s datetime input", want)
		}
	}
	// The markers are supplied by verifiably from the pickers above; they must
	// never be inputs. (Checked as `name="…"` rather than a bare substring, so
	// a comment explaining the marker doesn't trip it.)
	for _, bad := range []string{"validFromEpoch", "validUntilEpoch"} {
		if strings.Contains(src, `name="`+bad+`"`) {
			t.Errorf("%q is an internal template marker — it must never be a form input", bad)
		}
	}
}
