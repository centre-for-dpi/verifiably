package waltid

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/vctypes"
)

// syncIssuer2DisplayName publishes a custom mdoc schema's name through
// issuer-api2, then restarts that service so it republishes its wellknown.
//
// Every step is best-effort and NOTHING here can fail a schema save. That is a
// deliberate contract, matching CatalogPath's posture (config.go: "a deploy
// that hasn't bind-mounted the catalog file in still works"): the operator's
// schema is already persisted and already registered on the legacy path by the
// time we get here, and a wallet showing the raw docType is a cosmetic
// regression, not a reason to reject their work. Unmounted config, a read-only
// mount, an absent docker socket and a failed restart all degrade to a logged
// warning.
//
// Restart is gated on `changed` for the same reason appendCredentialType
// returns that bool, but the stakes are higher here: issuer-api2 IS the mdoc
// issuance path, so restarting it on a re-save that wrote nothing would take
// live issuance down for no gain.
func (a *Adapter) syncIssuer2DisplayName(schema vctypes.Schema) {
	if a.cfg.Issuer2MetadataPath == "" {
		return
	}
	if schema.Std != "mso_mdoc" {
		return
	}
	docType := mdocDocTypeFor(schema)
	if _, ok := profileIDForDocType(docType); !ok {
		// No pre-provisioned profile means this docType cannot be issued at all
		// (buildIssuer2Offer refuses it), so there is no configuration whose
		// display block would ever be read.
		slog.Warn("waltid: skipping issuer2 display-name sync, no profile for docType",
			"docType", docType, "schema", schema.ID)
		return
	}
	changed, err := setIssuer2Display(a.cfg.Issuer2MetadataPath, docType, schema)
	if err != nil {
		slog.Warn("waltid: could not publish mdoc credential name to issuer-api2 — the wallet will show the previous name",
			"docType", docType, "path", a.cfg.Issuer2MetadataPath, "err", err)
		return
	}
	if !changed {
		return
	}
	service := a.cfg.Issuer2ServiceName
	if service == "" {
		service = "issuer-api2"
	}
	if err := restartContainer(service); err != nil {
		slog.Warn("waltid: issuer-api2 metadata updated but restart failed — the new credential name appears on its next restart",
			"service", service, "err", err)
		return
	}
	// State.Running flips true well before issuer-api2 serves OID4VCI, and the
	// operator's very next action is typically to issue. Same wait the legacy
	// path does after its own restart; best-effort, proceeds on timeout.
	waitForHTTPReady(a.cfg.Issuer2BaseURL, 60*time.Second)
}

// setIssuer2Display rewrites the `display` block of ONE docType's configuration
// inside issuer-api2's credential-issuer-metadata.conf, so the name an operator
// typed into the schema builder is what their wallet shows.
//
// Why this exists at all. The legacy issuer-api path never needed it: an
// operator's schema becomes a brand-new catalog entry there (see
// appendCredentialType), and displayPair drops schema.Name straight into that
// entry's display[].name. issuer-api2 works the other way round — its
// configurations are PRE-PROVISIONED (one per ISO docType, pinned against
// deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf), and issuer2.go writes no
// metadata at all. So an mdoc schema had no channel by which its name could
// reach the wellknown, and the wallet fell back to the configuration id
// (`org.iso.18013.5.1.mDL` on the citizen's accept screen). This function is
// that missing channel: it does not create a configuration, it edits the
// display block of the one the docType already has.
//
// Returns changed=false when the file already carries exactly this display
// block, so the caller can skip the restart. That matters more here than on the
// legacy path: mdoc issuance itself runs through issuer-api2, so an
// unconditional restart on every schema save would interrupt live issuance for
// a no-op write.
//
// Shares catalogMu with appendCredentialType. The two functions touch different
// files, so the lock is stricter than strictly required — but a single mutex
// keeps "one save at a time" true across both catalogs without introducing a
// lock-ordering question, and schema saves are rare and human-paced.
func setIssuer2Display(metadataPath string, docType string, schema vctypes.Schema) (changed bool, err error) {
	catalogMu.Lock()
	defer catalogMu.Unlock()

	docType = strings.TrimSpace(docType)
	if docType == "" {
		return false, fmt.Errorf("issuer2 metadata: empty docType")
	}

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return false, fmt.Errorf("read issuer2 metadata: %w", err)
	}
	content := string(data)

	start, end, indent, ok := findConfigBlock(content, docType)
	if !ok {
		// The docType has no pre-provisioned configuration. Nothing to name —
		// and buildIssuer2Offer would already have refused to issue it, so this
		// is not a state a real save reaches. Report it rather than inventing
		// a configuration: issuer-api2 resolves profiles, not us.
		return false, fmt.Errorf(
			"issuer2 metadata: no credential configuration %q in %s", docType, metadataPath)
	}

	block := content[start:end]
	updated := replaceDisplayBlock(block, indent, buildIssuer2DisplayBlock(indent, schema))
	if updated == block {
		return false, nil
	}
	newContent := content[:start] + updated + content[end:]
	if err := os.WriteFile(metadataPath, []byte(newContent), 0o644); err != nil {
		return false, fmt.Errorf("write issuer2 metadata: %w", err)
	}
	return true, nil
}

// findConfigBlock locates the body of a `"<configID>" = { ... }` entry, brace
// counting from the opening `{` exactly as stripBlockEntry does. Returns the
// byte range of the body EXCLUDING the braces themselves, plus the indent of
// the opening line so a rewritten block matches the file's existing shape.
//
// Byte offsets rather than a parse-and-reserialise round trip: issuer-api2's
// shipped metadata carries comments, `${?VAR}` substitutions, duplicate keys
// (eu.europa.ec.eudi.pid.1 declares credential_metadata twice) and trailing
// commas that no Go HOCON writer would reproduce faithfully. Editing one
// configuration's bytes in place is the only way to satisfy the hard
// requirement that touching mDL leaves Photo ID — and everything else in the
// file — byte-identical.
func findConfigBlock(content, configID string) (start, end int, indent string, ok bool) {
	needle := `"` + configID + `"`
	search := 0
	for {
		i := strings.Index(content[search:], needle)
		if i == -1 {
			return 0, 0, "", false
		}
		i += search
		search = i + len(needle)

		// Must be a key: `"<id>" = {`, with only spaces between. This filters
		// out the many places the same string appears as a VALUE — scope,
		// doctype, and every claim path in credential_metadata all repeat the
		// docType verbatim, and matching one of those would splice a display
		// block into the middle of a claims array.
		rest := content[search:]
		trimmed := strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(trimmed, "=") {
			continue
		}

		afterEq := strings.TrimLeft(trimmed[1:], " \t\r\n")
		if !strings.HasPrefix(afterEq, "{") {
			continue
		}

		open := strings.Index(content[i:], "{")
		if open == -1 {
			return 0, 0, "", false
		}
		open += i

		// Indent of the line the key sits on — the rewritten display block is
		// nested one level (two spaces, matching this file) inside it.
		lineStart := strings.LastIndex(content[:i], "\n") + 1
		indent = content[lineStart:i]
		if strings.TrimSpace(indent) != "" {
			indent = ""
		}

		depth := 0
		for j := open; j < len(content); j++ {
			switch content[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				return open + 1, j, indent, true
			}
		}
		return 0, 0, "", false
	}
}

// replaceDisplayBlock swaps the configuration body's top-level `display = [...]`
// for a freshly rendered one, or appends it when the configuration has none.
//
// "Top-level" is load-bearing. A configuration body can contain a NESTED
// display list — Photo ID's credential_metadata block holds one per claim plus
// one of its own — and rewriting any of those would either destroy a claim
// label or leave the credential name in a place the wallet does not read.
// Depth counting from the body's own level keeps the edit on the outer one.
func replaceDisplayBlock(body, indent, rendered string) string {
	start, end, ok := findTopLevelDisplay(body)
	if !ok {
		// No display key. Append before the body's trailing whitespace so the
		// closing brace stays on its own line.
		trimmed := strings.TrimRight(body, " \t\r\n")
		tail := body[len(trimmed):]
		return trimmed + "\n" + rendered + tail
	}
	return body[:start] + strings.TrimLeft(rendered, " \t") + body[end:]
}

// findTopLevelDisplay returns the byte range of a `display = [ ... ]` assignment
// that sits at depth 0 of the given configuration body, brackets included, plus
// the run of indentation preceding it (so the replacement lands flush).
func findTopLevelDisplay(body string) (start, end int, ok bool) {
	depth := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{', '[':
			depth++
			continue
		case '}', ']':
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		if !strings.HasPrefix(body[i:], "display") {
			continue
		}
		// Must start a word — guards against `issuerDisplay`, and against the
		// substring inside any longer identifier a future walt.id release adds.
		if i > 0 {
			c := body[i-1]
			if c == '_' || c == '-' || c == '.' ||
				(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				continue
			}
		}
		after := strings.TrimLeft(body[i+len("display"):], " \t")
		if !strings.HasPrefix(after, "=") && !strings.HasPrefix(after, ":") {
			continue
		}
		open := strings.Index(body[i:], "[")
		if open == -1 {
			return 0, 0, false
		}
		open += i
		d := 0
		for j := open; j < len(body); j++ {
			switch body[j] {
			case '[':
				d++
			case ']':
				d--
			}
			if d == 0 {
				// Swallow the indentation before `display` so the replacement
				// supplies its own, and a trailing comma if one follows.
				s := i
				for s > 0 && (body[s-1] == ' ' || body[s-1] == '\t') {
					s--
				}
				e := j + 1
				if e < len(body) && body[e] == ',' {
					e++
				}
				return s, e, true
			}
		}
		return 0, 0, false
	}
	return 0, 0, false
}

// buildIssuer2DisplayBlock renders the display list for a pre-provisioned mdoc
// configuration from the operator's schema.
//
// ONE locale entry, "en". The static blocks this replaces carried both an "en"
// and an "es" name, because they were hand-written translations of a hardcoded
// string. A schema carries exactly ONE name, so there is no second string to
// publish: emitting the operator's single name twice, once labelled "es", would
// assert that "mDL" is the Spanish for "mDL" — a claim the operator never made,
// and one that actively hurts, because a wallet matching es-DO would stop at
// that phantom entry instead of continuing to a real translation. A wallet with
// no locale match falls back to the first entry, so a single "en" entry still
// renders for every holder; that is the same posture claimLocales already takes
// for per-field labels, which stopped synthesising an English label for fields
// that do not declare one.
//
// The coherent long-term answer is a credential-level equivalent of
// FieldSpec.Labels — the schema builder already collects free-form per-locale
// labels per claim, and a per-locale credential NAME would slot into the same
// UI and the same map shape, at which point this function emits one entry per
// declared locale exactly as buildClaimsBlock does. NOT built here: it needs a
// vctypes.Schema field, a builder form control, and a migration for schemas
// saved without it. Flagged for the plan.
//
// Colours are deliberately omitted rather than carried over from the static
// blocks. They were part of the same hardcoded guess as the name, they are not
// something the schema captures, and a wallet renders its own default card
// styling when they are absent — which is honest, where a retained #0B4F6C
// would be branding invented for an operator who never chose it.
func buildIssuer2DisplayBlock(indent string, schema vctypes.Schema) string {
	display, desc := displayPair(strings.TrimSpace(schema.Name), schema)
	in := indent + "  "
	var b strings.Builder
	fmt.Fprintf(&b, "%sdisplay = [\n", in)
	fmt.Fprintf(&b, "%s  {\n", in)
	fmt.Fprintf(&b, "%s    name = \"%s\"\n", in, hoconEscape(display))
	fmt.Fprintf(&b, "%s    description = \"%s\"\n", in, hoconEscape(desc))
	fmt.Fprintf(&b, "%s    locale = \"en\"\n", in)
	fmt.Fprintf(&b, "%s  }\n", in)
	fmt.Fprintf(&b, "%s]", in)
	return b.String()
}
