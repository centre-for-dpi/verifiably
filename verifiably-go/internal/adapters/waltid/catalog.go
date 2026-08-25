package waltid

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/verifiably/verifiably-go/vctypes"
)

// catalogMu serialises edits to credential-issuer-metadata.conf. Two custom
// schemas saved in quick succession would otherwise race on the read-modify-
// write of the HOCON file. Using package-level state is fine — the file is
// pinned to a single host path and only one verifiably-go process touches it.
var catalogMu sync.Mutex

// appendCredentialType registers a custom schema in walt.id's HOCON catalog
// (credential-issuer-metadata.conf) so its configurationIds become real
// members of credential_configurations_supported. Without this, walt.id rejects
// any configurationId it didn't see at boot — the borrow trick worked around
// this in Phase 0 by signing under a stock walt.id config; Phase 1+2 makes
// custom schemas first-class.
//
// Phase 2 fans out one Save into multiple catalog entries — one per wire
// format walt.id supports for the schema's Std. A w3c_vcdm_2 schema lands as
// jwt_vc_json + jwt_vc_json-ld + ldp_vc; an SD-JWT schema lands as vc+sd-jwt;
// an mdoc schema lands as mso_mdoc. This is what gives operators a "genuinely
// custom schema usable in every walt.id-supported format" — the original
// requirement from the catalog-edit redesign.
//
// Returns:
//   primary  — the configID matching the schema's default wire format, what
//              IssueToWallet reaches for in the common path
//   all      — every configID written to the catalog (for registeredConfigIDs)
//   changed  — true if at least one entry was newly written; false on a re-save
//              of an already-registered schema (idempotent)
//
// Concurrent callers serialise via catalogMu.
func appendCredentialType(catalogPath string, schema vctypes.Schema) (primary string, all []string, changed bool, err error) {
	catalogMu.Lock()
	defer catalogMu.Unlock()

	typeName := customSchemaTypeName(schema)
	wireFormats := waltidWireFormatsForStd(schema.Std)
	if len(wireFormats) == 0 {
		return "", nil, false, fmt.Errorf("walt.id catalog: no wire formats registered for Std=%q", schema.Std)
	}
	primary = typeName + "_" + wireFormats[0]

	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return "", nil, false, fmt.Errorf("read catalog: %w", err)
	}
	content := string(data)

	// Build the union of new entries — skipping any that already exist.
	// Only the per-format block form is emitted (no simple-array shorthand):
	//   - The shorthand `Foo = [VerifiableCredential, Foo],` only ever
	//     expands to a `Foo_jwt_vc_json` config inside walt.id, duplicating
	//     the explicit block we already write.
	//   - Worse, dotted typeNames (e.g. mdoc's `org.iso.18013.5.1.mDL`) get
	//     parsed by HOCON as nested objects (`org = { iso = { ... } }`),
	//     breaking walt.id's CredentialTypeConfig deserialiser with
	//     `Field 'format' is required` because the synthesised entry lacks
	//     a format key. Live integration test on 2026-04-29 confirmed this.
	// The block form alone is canonical, deterministic, and works for every
	// wire format walt.id supports.
	var blocks []string
	for _, wf := range wireFormats {
		configID := typeName + "_" + wf
		all = append(all, configID)
		if strings.Contains(content, `"`+configID+`"`) {
			continue
		}
		blocks = append(blocks, buildCredentialTypeEntry(configID, typeName, wf, schema))
		changed = true
	}
	if !changed {
		return primary, all, false, nil
	}

	lastBrace := strings.LastIndex(content, "}")
	if lastBrace == -1 {
		return "", nil, false, fmt.Errorf("invalid HOCON: no closing brace in %s", catalogPath)
	}

	var insert strings.Builder
	insert.WriteString("\n")
	for _, b := range blocks {
		insert.WriteString("\n")
		insert.WriteString(b)
		insert.WriteString("\n")
	}
	newContent := content[:lastBrace] + insert.String() + content[lastBrace:]
	if err := os.WriteFile(catalogPath, []byte(newContent), 0o644); err != nil {
		return "", nil, false, fmt.Errorf("write catalog: %w", err)
	}
	sort.Strings(all)
	return primary, all, true, nil
}

// customSchemaTypeName returns the catalog/VC-type identifier for a custom
// schema. Prefers an explicitly-declared AdditionalType (via the builder's
// "Extra Type" field) so an operator who knows the canonical name can pin it;
// falls back to a CamelCased version of the schema name. Mirrors the type
// chosen in buildCredentialData so the catalog entry, the VC's `type` array
// and the configurationId all align.
func customSchemaTypeName(schema vctypes.Schema) string {
	if len(schema.AdditionalTypes) > 0 && strings.TrimSpace(schema.AdditionalTypes[0]) != "" {
		return strings.TrimSpace(schema.AdditionalTypes[0])
	}
	return sanitizeTypeName(schema.Name)
}

// waltidWireFormatsForStd returns the walt.id wire-format keys that should be
// registered for a given Std. The primary (most-tested in walt.id's E2E
// suite) wire format is first — appendCredentialType uses [0] as the configID
// IssueToWallet defaults to.
//
// The list mirrors verifiably-go's existing formatToStd reverse mapping but
// excludes formats walt.id can issue but the verifier can't match against
// (jwt_vc, dc+sd-jwt) — the verifier round-trip is what users actually need
// for a end-to-end demo. Operators who specifically need the legacy/jwt
// formats can edit the catalog manually; this hook keeps the demo set
// curated.
func waltidWireFormatsForStd(std string) []string {
	switch std {
	case "w3c_vcdm_2", "":
		return []string{"jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"}
	case "w3c_vcdm_1", "jwt_vc":
		return []string{"jwt_vc_json"}
	// Accept both spellings for SD-JWT VC. The schema-builder dropdown emits
	// the bare "sd_jwt_vc" (parens + spaces in <option value=> are awkward);
	// the canonical form used in walt.id metadata + adapter switches is the
	// parenthesised one. The canonicalStd shim normalises at the form
	// boundary, but accepting both here also covers in-memory schemas saved
	// before that shim shipped.
	case "sd_jwt_vc (IETF)", "sd_jwt_vc":
		return []string{"vc+sd-jwt"}
	case "mso_mdoc":
		return []string{"mso_mdoc"}
	}
	return nil
}

// buildCredentialTypeEntry renders a HOCON block for one wire format. The
// shape varies because walt.id's CredentialTypeConfig deserialiser keys off
// different fields per format: JWT/LDP credentials use credential_definition
// (with @context for LDP variants), SD-JWT uses vct, mdoc uses doctype.
// Trying to use a single uniform shape produces walt.id boot errors.
func buildCredentialTypeEntry(configID, typeName, wireFormat string, schema vctypes.Schema) string {
	switch wireFormat {
	case "jwt_vc_json", "jwt_vc":
		return buildJWTVCJsonEntry(configID, typeName, wireFormat, schema)
	case "jwt_vc_json-ld", "ldp_vc":
		return buildLinkedDataEntry(configID, typeName, wireFormat, schema)
	case "vc+sd-jwt", "dc+sd-jwt":
		return buildSDJWTEntry(configID, typeName, wireFormat, schema)
	case "mso_mdoc":
		return buildMDocEntry(configID, typeName, schema)
	default:
		// Should never hit — waltidWireFormatsForStd is the only caller and
		// it lists exactly the formats above. Defensive: fall back to the
		// JWT shape so a future Std mapping bug surfaces as a parse error
		// rather than a silent skip.
		return buildJWTVCJsonEntry(configID, typeName, wireFormat, schema)
	}
}

// buildJWTVCJsonEntry: the canonical W3C VC + JWT wrapping. Walt.id signs
// these as JWS + DID-bound holder. EdDSA + ES256 are the two curves walt.id
// supports out of the box; listing both keeps the configuration usable
// regardless of which curve the issuer DID was onboarded with.
func buildJWTVCJsonEntry(configID, typeName, wireFormat string, schema vctypes.Schema) string {
	display, desc := displayPair(typeName, schema)
	return fmt.Sprintf(`    "%s" = {
        format = "%s"
        cryptographic_binding_methods_supported = ["did"]
        credential_signing_alg_values_supported = ["EdDSA", "ES256"]
        credential_definition = {
            type = ["VerifiableCredential", "%s"]
        }
        display = [
            {
                name = "%s"
                description = "%s"
                locale = "en-US"
                background_color = "#FFFFFF"
                text_color = "#000000"
            }
        ]
%s    }`, configID, wireFormat, typeName, hoconEscape(display), hoconEscape(desc), buildClaimsBlock(schema.FieldsSpec, ""))
}

// buildLinkedDataEntry covers both jwt_vc_json-ld (JSON-LD payload, JWT
// envelope) and ldp_vc (JSON-LD with a Linked Data Proof). Both need the
// @context array because the Kotlin parser wires it through to the VC
// builder; without it the issued credential has no @context and fails
// downstream JSON-LD canonicalisation.
//
// Heads-up: walt.id 0.18.2's verifier-api can't match ldp_vc presentations
// (parsedDocument is empty in the wallet), so credentials issued in this
// format are issue-only end-to-end. The UI surfaces an "issue-only" badge
// for these — see verifierSupportsFormat.
func buildLinkedDataEntry(configID, typeName, wireFormat string, schema vctypes.Schema) string {
	display, desc := displayPair(typeName, schema)
	return fmt.Sprintf(`    "%s" = {
        format = "%s"
        cryptographic_binding_methods_supported = ["did"]
        credential_signing_alg_values_supported = ["EdDSA", "ES256"]
        credential_definition = {
            "@context" = [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/ns/credentials/examples/v1"
            ]
            type = ["VerifiableCredential", "%s"]
        }
        display = [
            {
                name = "%s"
                description = "%s"
                locale = "en-US"
                background_color = "#FFFFFF"
                text_color = "#000000"
            }
        ]
%s    }`, configID, wireFormat, typeName, hoconEscape(display), hoconEscape(desc), buildClaimsBlock(schema.FieldsSpec, ""))
}

// buildSDJWTEntry covers vc+sd-jwt (the older media type) and dc+sd-jwt
// (the IETF draft's newer name). SD-JWT VC keys off `vct` not
// `credential_definition.type`. Walt.id's verifier matches presentations
// against the exact vct string the issuer advertised, so all three
// touchpoints (catalog vct here, ir.Vct in IssueToWallet, tpl.Vct in
// the verifier handler) must use the same string for the round-trip
// to work.
//
// We pin the vct to the host-derived URL schema.CredentialVct(publicBase) =
// VERIFIABLY_PUBLIC_URL/credentials/<schema.ID> — the SAME string the Inji
// issuers embed and the verifier handler requests (verifier.go's
// picked.CredentialVct). It is a FIXED value verifiably computes from its own
// VERIFIABLY_PUBLIC_URL (NOT a HOCON ${...} that resolves at walt.id boot),
// so every layer reconstructs it identically:
//   - catalog vct here (walt.id signs the SD-JWT's vct from this config),
//   - ir.Vct in IssueToWallet (case req.Schema.Vct != "" reads it back via
//     ApplyVariant), and
//   - tpl.Vct in the verifier handler (CredentialVct, whether it reads the
//     catalog Vct or recomputes it — both now yield the same URL).
// The earlier bare-type-name form (e.g. "FarmerCredential") pre-dated the
// host-derived convention; once the verifier moved to CredentialVct the bare
// name stranded walt.id SD-JWTs — the wallet held vct="FarmerCredential" while
// the verifier requested the URL, so Credo reported "No credential found" (F8).
func buildSDJWTEntry(configID, typeName, wireFormat string, schema vctypes.Schema) string {
	display, desc := displayPair(typeName, schema)
	// Host-derived vct — matches schema.CredentialVct in the verifier and the
	// Inji issuers. Empty VERIFIABLY_PUBLIC_URL falls back to localhost:8080
	// inside CredentialVct (dev only); prod always has it set.
	vct := schema.CredentialVct(strings.TrimRight(os.Getenv("VERIFIABLY_PUBLIC_URL"), "/"))
	// walt.id 0.18.2's CredentialSupported deserializer accepts `display`
	// regardless of format — verified empirically (catalog round-trip
	// against waltid/issuer-api:0.18.2): adding a display block to a
	// vc+sd-jwt entry surfaces it verbatim in the published wellknown.
	// Earlier this builder dropped the schema arg; consequence was that
	// every SD-JWT credential's wallet card rendered with a blank title +
	// no description, even though the schema-builder UI captured both.
	return fmt.Sprintf(`    "%s" = {
        format = "%s"
        cryptographic_binding_methods_supported = ["jwk"]
        credential_signing_alg_values_supported = ["ES256"]
        vct = "%s"
        display = [
            {
                name = "%s"
                description = "%s"
                locale = "en-US"
                background_color = "#FFFFFF"
                text_color = "#000000"
            }
        ]
%s    }`, configID, wireFormat, vct, hoconEscape(display), hoconEscape(desc), buildClaimsBlock(schema.FieldsSpec, ""))
}

// buildMDocEntry covers mso_mdoc — the ISO 18013-5 mobile document format.
// Mdoc is keyed by `doctype` (not type or vct), and binds via cose_key
// (jwt proofs, ES256 only — that's what walt.id's mdoc signer emits). cwt was
// removed from OID4VCI 1.0 final (openid/OpenID4VCI#369) and no real holder
// generates it, including Credo-TS, which this project uses. See the sibling
// fix in this file's other mso_mdoc entry builder, commit 1ac0c7d — this one
// was missed by it, being a separate code path for custom schemas. The
// doctype namespacing convention is an inverted-DNS string; if the operator
// pinned an AdditionalType we use that verbatim, else we fall back to the
// sanitized type name so the doctype is at least stable across restarts.
//
// `display` is emitted alongside the format-specific fields for the same
// reason as buildSDJWTEntry: walt.id's CredentialSupported deserializer
// accepts it for every format. The earlier comment that "Mdoc credentials
// don't carry display metadata in walt.id's catalog format" was wrong —
// walt.id v0.18.2's wellknown serializer round-trips display verbatim
// regardless of format.
func buildMDocEntry(configID, typeName string, schema vctypes.Schema) string {
	doctype := strings.TrimSpace(schema.Vct)
	if doctype == "" && len(schema.AdditionalTypes) > 0 {
		doctype = strings.TrimSpace(schema.AdditionalTypes[0])
	}
	if doctype == "" {
		doctype = typeName
	}
	display, desc := displayPair(typeName, schema)
	// mdoc claims are namespace-keyed (see buildSelectiveInputDescriptor in
	// verifier.go and walt.id's own shipped issuer2 metadata), so the claims
	// block's path needs the base namespace, not just the field name.
	//
	// Prefer docTypeProfiles: it carries the correct namespace per known
	// docType, including Photo ID, where mdocNamespaceFor's dot-stripping
	// heuristic gives the wrong answer (org.iso.23220.photoid.1 strips to
	// org.iso.23220.photoid; the real namespace is org.iso.23220.1). Do not
	// "simplify" this to mdocNamespaceFor alone — that regresses Photo ID.
	namespace := mdocNamespaceFor(doctype)
	if p, ok := profileIDForDocType(doctype); ok {
		namespace = p.baseNamespace
	}
	return fmt.Sprintf(`    "%s" = {
        format = "mso_mdoc"
        cryptographic_binding_methods_supported = ["cose_key"]
        credential_signing_alg_values_supported = ["ES256"]
        proof_types_supported = { jwt = { proof_signing_alg_values_supported = ["ES256"] } }
        doctype = "%s"
        display = [
            {
                name = "%s"
                description = "%s"
                locale = "en-US"
                background_color = "#FFFFFF"
                text_color = "#000000"
            }
        ]
%s    }`, configID, hoconEscape(doctype), hoconEscape(display), hoconEscape(desc), buildClaimsBlock(schema.FieldsSpec, namespace))
}

// displayPair derives the human-readable name + description from the
// schema, falling back to the type name when fields are blank or the
// builder's "—" placeholder. Centralised so each format builder gets
// the same fallback behaviour without copy-paste.
//
// When Schema.IssuerDisplayName is populated, it's appended to the
// description as " · Issued by <name>" — walt.id 0.18.2's per-credential
// display block has no dedicated issuer field, so composition into
// description is the only surface that propagates across all formats.
// Wallets render description as a subtitle on the credential card.
func displayPair(typeName string, schema vctypes.Schema) (display, desc string) {
	display = strings.TrimSpace(schema.Name)
	if display == "" {
		display = typeName
	}
	desc = strings.TrimSpace(schema.Desc)
	if desc == "" || desc == "—" {
		desc = display
	}
	if iss := strings.TrimSpace(schema.IssuerDisplayName); iss != "" {
		desc = desc + " · Issued by " + iss
	}
	return display, desc
}

// buildClaimsBlock renders the OID4VCI claims metadata for a schema's
// fields, with one display entry per configured locale.
//
// This is the mechanism that lets a wallet show "Apellidos" to a
// Spanish-speaking holder instead of the raw identifier. Without it, wallets
// derive a label from the identifier themselves — which is why cdpi-wallet
// shows "Family Name" today regardless of the holder's language.
//
// namespace picks BOTH which walt.id field is emitted and its shape — the
// two destination services model claim metadata with unrelated Kotlin
// types, confirmed by decompiling each service's own jar:
//   - "" (W3C VC-JWT, LinkedData, SD-JWT — all served by the LEGACY
//     issuer-api, package id.walt.oid4vc.data): emits `credentialSubject`,
//     a flat Map<String, ClaimDescriptor> keyed by field name.
//     CredentialSupported.claims exists on this type too, but it is
//     Map<String, Map<String, ClaimDescriptor>> — namespace-keyed, always
//     two levels deep — and ClaimDescriptor has no `path` field at all. A
//     flat format has no second-level key to give it, so `claims` is not
//     usable here.
//   - non-empty (mso_mdoc — served by issuer-api2, package
//     id.walt.openid4vci.metadata.issuer): emits `claims` as an array of
//     {path, display} entries, path being the two-element
//     ["<namespace>", "<field>"] form — see verifier.go's
//     buildSelectiveInputDescriptor and walt.id's own shipped metadata
//     (deploy/k8s/config/issuer2/credential-issuer-metadata.conf).
//
// Emitting the mdoc array shape for a flat format crash-loops the legacy
// issuer-api container before its web server binds: CIProvider.<init> throws
// JsonDecodingException ("Expected JsonObject, but had JsonArray … at path:
// $.claims") while parsing the first non-mdoc entry, which is why
// credential-issuer-metadata.conf never listens on its port at all. See the
// 2026-08-24 incident: POST /onboard/issuer failed with connection refused
// because issuer-api never came up.
//
// Returns "" for a schema with no declared fields (stock catalog entries):
// an empty block is not valid HOCON here, and omitting it preserves exactly
// today's behaviour for those schemas.
func buildClaimsBlock(fields []vctypes.FieldSpec, namespace string) string {
	if len(fields) == 0 {
		return ""
	}
	if namespace == "" {
		return buildCredentialSubjectBlock(fields)
	}
	var b strings.Builder
	b.WriteString("        claims = [\n")
	for _, f := range fields {
		if f.Name == "" {
			continue
		}
		b.WriteString("            {\n")
		fmt.Fprintf(&b, "                path = [\"%s\", \"%s\"]\n", hoconEscape(namespace), hoconEscape(f.Name))
		b.WriteString("                display = [\n")

		locales := claimLocales(f)
		for _, loc := range locales {
			fmt.Fprintf(&b,
				"                    { name = \"%s\", locale = \"%s\" }\n",
				hoconEscape(f.Label(loc)), hoconEscape(loc))
		}
		b.WriteString("                ]\n")
		b.WriteString("            }\n")
	}
	b.WriteString("        ]\n")
	return b.String()
}

// buildCredentialSubjectBlock renders the legacy issuer-api's flat claim
// metadata field — CredentialSupported.credentialSubject, a
// Map<String, ClaimDescriptor> keyed by field name — for the non-mdoc
// formats (W3C VC-JWT, LinkedData, SD-JWT). See buildClaimsBlock's doc
// comment for why this field, not `claims`, is what legacy issuer-api
// expects.
func buildCredentialSubjectBlock(fields []vctypes.FieldSpec) string {
	var b strings.Builder
	b.WriteString("        credentialSubject = {\n")
	for _, f := range fields {
		if f.Name == "" {
			continue
		}
		fmt.Fprintf(&b, "            %s = {\n", hoconEscape(f.Name))
		b.WriteString("                display = [\n")

		locales := claimLocales(f)
		for _, loc := range locales {
			fmt.Fprintf(&b,
				"                    { name = \"%s\", locale = \"%s\" }\n",
				hoconEscape(f.Label(loc)), hoconEscape(loc))
		}
		b.WriteString("                ]\n")
		b.WriteString("            }\n")
	}
	b.WriteString("        }\n")
	return b.String()
}

// claimLocales returns the locales to emit for a field: the ones it actually
// declares, English first when present and the rest sorted so catalog output
// is deterministic (the file is diffed and written on every schema save).
//
// English is NO LONGER synthesised for a field that doesn't declare it. It
// used to be, on the reasoning that Label("en") falls back to the derived
// name so there is always something to show — but the schema builder's base
// language is now a value the operator sets rather than a hardcoded "en". A
// deployment issuing only in Spanish declares {"es": "Apellidos"} and no
// English at all; synthesising an "en" entry there published a phantom
// English label carrying the DERIVED identifier ("Family Name" from
// family_name), which is not a translation the issuer ever authored and which
// a wallet would prefer over the Spanish for any en-* holder.
//
// English keeps its position at the FRONT when the field does declare it:
// vctypes.FieldSpec.Label still falls back to "en" for an unresolvable
// locale, so it remains the base language of the data model even though it is
// no longer mandatory in the form.
//
// A field with no labels at all yields no locales, and buildClaimsBlock then
// emits an empty display list — the wallet derives a label from the
// identifier itself, exactly as it did before any of this metadata existed.
func claimLocales(f vctypes.FieldSpec) []string {
	out := make([]string, 0, len(f.Labels))
	for loc := range f.Labels {
		if loc == "en" {
			continue
		}
		out = append(out, loc)
	}
	sort.Strings(out)
	if _, ok := f.Labels["en"]; ok {
		return append([]string{"en"}, out...)
	}
	return out
}

// hoconEscape prepares a free-text string for inclusion in a HOCON quoted
// string literal: backslashes first (so we don't double-escape the ones we
// add), then double quotes, then the control characters a quoted string
// cannot contain literally (newline, carriage return, tab). HOCON otherwise
// treats `"` inside a quoted string as the terminator and silently
// truncates, and a raw newline/CR/tab breaks the file across lines or
// columns.
//
// This escaping must stay strictly additive: well-formed input (no
// backslash, quote, or control character) must render byte-for-byte as
// before. Callers include locale codes, which became free-form operator
// text once this task added per-locale claim display — do not trim or
// reject here, only escape.
func hoconEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// removeCredentialType deletes every catalog entry written for a custom
// schema — the simple-array form plus all per-format blocks. Idempotent;
// missing entries are silently skipped so a Phase-1-→-Phase-2 schema
// (which only has a jwt_vc_json entry) still cleans up correctly.
func removeCredentialType(catalogPath string, schema vctypes.Schema) error {
	catalogMu.Lock()
	defer catalogMu.Unlock()

	typeName := customSchemaTypeName(schema)
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return fmt.Errorf("read catalog: %w", err)
	}
	content := string(data)
	updated := stripSimpleEntry(content, typeName)
	for _, wf := range waltidWireFormatsForStd(schema.Std) {
		updated = stripBlockEntry(updated, typeName+"_"+wf)
	}
	if updated == content {
		return nil
	}
	return os.WriteFile(catalogPath, []byte(updated), 0o644)
}

// stripSimpleEntry removes a `    TypeName = [VerifiableCredential, TypeName],`
// line from the HOCON content. Tolerates leading whitespace variation.
func stripSimpleEntry(content, typeName string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	prefix := typeName + " ="
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) && strings.Contains(trimmed, "[VerifiableCredential") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// stripBlockEntry removes a `"<configID>" = { ... }` block by counting braces
// from the opening `{` until they balance. Walt.id's HOCON entries don't
// nest unbalanced braces so byte-counting is sufficient.
func stripBlockEntry(content, configID string) string {
	needle := `"` + configID + `" =`
	start := strings.Index(content, needle)
	if start == -1 {
		return content
	}
	open := strings.Index(content[start:], "{")
	if open == -1 {
		return content
	}
	open += start
	depth := 0
	end := -1
	for i := open; i < len(content); i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
		if depth == 0 {
			end = i + 1
			break
		}
	}
	if end == -1 {
		return content
	}
	for end < len(content) && (content[end] == '\n' || content[end] == '\r' || content[end] == ' ' || content[end] == '\t') {
		end++
	}
	return content[:start] + content[end:]
}
