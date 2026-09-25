// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The audit actions of the identity page (ADR-039 decision 1).
const (
	ActionProvisionIdentity = "issuance.ProvisionIdentity"
	ActionImportIdentity    = "issuance.ImportIdentity"
	ActionRequestTrust      = "issuance.RequestTrustEntry"
)

// DIDDocumentPath is where a did:web of the host of the pair resolves.
const DIDDocumentPath = "/.well-known/did.json"

// MaxFormBytes caps a posted identity form. A PEM chain of a few
// certificates fits many times.
const MaxFormBytes = 256 << 10

// Identity reads and changes the issuer identity of the adapter of the
// pair (ADR-046 decision 1).
type Identity interface {
	GetIssuerIdentity(context.Context, *connect.Request[backendv1.GetIssuerIdentityRequest]) (
		*connect.Response[backendv1.GetIssuerIdentityResponse], error)
	ProvisionIssuerIdentity(context.Context, *connect.Request[backendv1.ProvisionIssuerIdentityRequest]) (
		*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error)
	ImportIssuerIdentity(context.Context, *connect.Request[backendv1.ImportIssuerIdentityRequest]) (
		*connect.Response[backendv1.ImportIssuerIdentityResponse], error)
}

// Trust reads and writes one entry of a trust registry.
type Trust interface {
	GetEntry(context.Context, *connect.Request[trustv1.GetEntryRequest]) (*connect.Response[trustv1.GetEntryResponse], error)
	UpsertEntry(context.Context, *connect.Request[trustv1.UpsertEntryRequest]) (*connect.Response[trustv1.UpsertEntryResponse], error)
}

// The import kinds of "Bring your own".
const (
	kindDID  = "did"
	kindX509 = "x509"
)

// identityView is what the identity page shows.
type identityView struct {
	caps     *backendv1.GetCapabilitiesResponse
	identity *backendv1.IssuerIdentity
	// state is "none", "registered", "stack" (the stack keeps its own
	// identity), or "down".
	state    string
	trustURL string
	entry    *trustv1.TrustEntry
	// form keeps the values and the errors of a posted form.
	form   url.Values
	errs   map[string]string
	kind   string
	toasts []components.Toast
}

// identity draws board Issuer-Identity: the current status, "Start
// instantly", and "Bring your own".
func (p *Pages) identity(pg page) error {
	v := p.identityView(pg)
	v.kind = pg.r.URL.Query().Get("kind")
	v.toasts = identityNotice(pg.r.URL.Query())
	return p.renderIdentity(pg, v)
}

// identityView reads the capabilities, the identity, the trust registry
// of the deployment, and the entry of the identity there.
func (p *Pages) identityView(pg page) identityView {
	ctx := pg.r.Context()
	v := identityView{caps: p.caps(pg), state: "none", trustURL: trustRegistry(pg.f)}
	if p.opts.Identity == nil {
		v.state = "stack"
		return v
	}
	res, err := p.opts.Identity.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	switch {
	case connect.CodeOf(err) == connect.CodeUnimplemented:
		v.state = "stack"
	case err != nil:
		v.state = "down"
	case res.Msg.GetIdentity() != nil && len(res.Msg.GetIdentity().GetIdentifiers()) > 0:
		v.state, v.identity = "registered", res.Msg.GetIdentity()
	}
	if v.identity != nil && v.trustURL != "" && p.opts.Trust != nil {
		got, gerr := p.opts.Trust(v.trustURL).GetEntry(ctx, connect.NewRequest(&trustv1.GetEntryRequest{
			Identifier: trustIdentifier(v.identity.GetIdentifiers()[0]),
		}))
		if gerr == nil {
			v.entry = got.Msg.GetEntry()
		}
	}
	return v
}

// trustRegistry returns the internal URL of the trust registry of the
// first live admin pair, in stack order (open question G.1), or "".
func trustRegistry(f staffshell.Frame) string {
	for _, st := range f.Live(commonv1.Role_ROLE_ADMIN) {
		if u := st.Peer.Services["trust-registry"]; u != "" {
			return u
		}
	}
	return ""
}

// trustIdentifier names an identity in the trust registry: a DID, or
// the subject of an X.509 leaf.
func trustIdentifier(id string) *trustv1.TrustEntry_Identifier {
	if strings.HasPrefix(id, "did:") {
		return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: id}}
	}
	return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: id}}
}

// identityNotice turns the notice of a redirect into toasts.
func identityNotice(q url.Values) []components.Toast {
	id := q.Get("id")
	var out []components.Toast
	for _, n := range strings.Split(q.Get("notice"), ",") {
		switch n {
		case "registered":
			out = append(out, components.Toast{Level: "ok", Text: msg.T("issuer.identity.registered", id)})
		case "trust_requested":
			out = append(out, components.Toast{Level: "ok", Text: msg.T("issuer.identity.trust.requested", id)})
		case "trust_kept":
			out = append(out, components.Toast{Level: "info", Text: msg.T("issuer.identity.trust.kept", id)})
		case "trust_failed":
			out = append(out, components.Toast{Level: "warn", Text: msg.T("issuer.identity.trust.failed", id)})
		}
	}
	return out
}

// renderIdentity writes the identity page.
func (p *Pages) renderIdentity(pg page, v identityView) error {
	b := p.blocks()
	csrf := staffsession.HiddenField(pg.r.Context())
	parts := []template.HTML{p.statusBlock(b, v)}
	if v.state != "stack" && v.state != "down" {
		if has(v.caps, backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION) {
			parts = append(parts, p.instantBlock(b, v, csrf))
		}
		if kinds := importKinds(v.caps); len(kinds) > 0 {
			parts = append(parts, p.ownBlock(b, v, kinds, csrf))
		}
	}
	back := b.add("button", components.Button{Text: msg.T("issuer.identity.back.label"), Href: HomePath})
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.nav.identity.label"), Lead: msg.T("issuer.identity.lead"),
		Description: msg.T("issuer.identity.lead"), Actions: back,
		Content: components.Join(parts...), Toasts: v.toasts,
	})
}

// statusBlock is the current status: the identity with its key, its
// metadata, and its entry in the trust registry.
func (p *Pages) statusBlock(b *blocks, v identityView) template.HTML {
	block := components.Block{ID: "status", Title: msg.T("issuer.identity.status.label")}
	switch v.state {
	case "stack":
		block.Lead = msg.T("issuer.identity.status.stack", stackName(v.caps))
	case "down":
		block.Lead = msg.T("issuer.identity.status.down")
	case "none":
		block.Meta = msg.T("issuer.identity.status.none.label")
		block.Lead = msg.T("issuer.identity.status.none")
	default:
		block.Meta = msg.T("issuer.identity.status.registered.label")
		block.Body = p.identityTable(b, v)
	}
	if v.trustURL == "" && v.state != "stack" {
		block.Body = components.Join(block.Body, b.add("note", components.Note{Text: msg.T("issuer.identity.trust.none_registry")}))
	}
	return b.add("block", block)
}

// identityTable lists the parts of a registered identity.
func (p *Pages) identityTable(b *blocks, v identityView) template.HTML {
	id := v.identity
	row := func(key string, cell components.Cell) components.Row {
		return components.Row{{Text: msg.T(key)}, cell}
	}
	rows := []components.Row{row("issuer.identity.identifier.label", components.Cell{Text: strings.Join(id.GetIdentifiers(), ", ")})}
	keyText := id.GetKey().GetType()
	if keyText == "" {
		keyText = id.GetKey().GetBackend()
	}
	rows = append(rows, row("issuer.identity.key.label", components.Cell{Text: msg.T("issuer.identity.key.text", keyText)}))
	if n := len(id.GetX5C()); n > 0 {
		rows = append(rows, row("issuer.identity.x509.label", components.Cell{Text: msg.T("issuer.identity.x509.value.label", strconv.Itoa(n))}))
	}
	if name := id.GetMetadata().GetDisplayName(); name != "" {
		rows = append(rows, row("issuer.identity.org.label", components.Cell{Text: name}))
	}
	if legal := id.GetMetadata().GetLegalIdentifier(); legal != "" {
		rows = append(rows, row("issuer.identity.legal.label", components.Cell{Text: legal}))
	}
	if v.trustURL != "" {
		rows = append(rows, row("issuer.identity.trust.label", components.Cell{HTML: b.add("badge", trustBadge(v.entry))}))
	}
	return b.add("table", components.Table{
		ID: "identity", Caption: msg.T("issuer.identity.caption.label"),
		Columns: []string{msg.T("issuer.identity.column.item.label"), msg.T("issuer.identity.column.value.label")}, Rows: rows,
	})
}

// trustBadge names the state of the entry of the identity.
func trustBadge(e *trustv1.TrustEntry) components.Badge {
	switch e.GetStatus() {
	case trustv1.Status_STATUS_PENDING:
		return components.Badge{Status: "warn", Text: msg.T("issuer.identity.trust.pending.label")}
	case trustv1.Status_STATUS_ACTIVE:
		return components.Badge{Status: "ok", Text: msg.T("issuer.identity.trust.active.label")}
	case trustv1.Status_STATUS_UNSPECIFIED:
		return components.Badge{Status: "info", Text: msg.T("issuer.identity.trust.none.label")}
	}
	return components.Badge{Status: "bad", Text: msg.T("issuer.identity.trust.other.label")}
}

// instantBlock is "Start instantly": one form that asks the stack for a
// key and an identifier. The stack keeps the key (ADR-001 decision 3).
func (p *Pages) instantBlock(b *blocks, v identityView, csrf template.HTML) template.HTML {
	methods := v.caps.GetDidMethods()
	method := pick(v.form.Get("method"), methods, "did:web")
	keyType := pick(v.form.Get("key_type"), v.caps.GetKeyTypes(), "Ed25519")
	options := func(values []string, selected string) []components.Option {
		out := make([]components.Option, 0, len(values))
		for _, x := range values {
			out = append(out, components.Option{Value: x, Text: x, Selected: x == selected})
		}
		return out
	}
	fields := components.Join(
		b.add("field", components.Field{ID: "method", Label: msg.T("issuer.identity.method.label"), Type: "select",
			Options: options(methods, method), Hint: msg.T("issuer.identity.method.hint"), Error: v.errs["method"]}),
		b.add("field", components.Field{ID: "key_type", Label: msg.T("issuer.identity.key_type.label"), Type: "select",
			Options: options(v.caps.GetKeyTypes(), keyType), Hint: msg.T("issuer.identity.instant.key")}),
		p.trustChoice(b, v, "instant-trust"),
		b.add("button", components.Button{Text: msg.T("issuer.identity.instant.submit.label"), Type: "submit", Variant: "primary"}),
	)
	body := formHTML(IdentityPath+"provision", csrf, fields)
	return b.add("block", components.Block{
		ID: "instant", Title: msg.T("issuer.identity.instant.label"), Meta: msg.T("issuer.identity.fastest.label"),
		Lead: msg.T("issuer.identity.instant.text"),
		Body: components.Join(body, b.add("note", components.Note{Text: msg.T("issuer.identity.instant.reversible")})),
	})
}

// pick returns want when the list holds it, else the fallback when the
// list holds that, else the first entry.
func pick(want string, list []string, fallback string) string {
	for _, v := range []string{want, fallback} {
		for _, x := range list {
			if x == v && v != "" {
				return v
			}
		}
	}
	if len(list) > 0 {
		return list[0]
	}
	return ""
}

// trustChoice is the box that asks the trust registry for an entry. It
// shows only when a live admin pair runs a trust registry.
func (p *Pages) trustChoice(b *blocks, v identityView, id string) template.HTML {
	if v.trustURL == "" {
		return ""
	}
	checked := v.form == nil || v.form.Get("trust") == "yes"
	return b.add("choice", components.Choice{
		ID: id, Name: "trust", Legend: msg.T("issuer.identity.trust.choice.label"), Multiple: true,
		Options: []components.ChoiceOption{{Value: "yes", Title: msg.T("issuer.identity.trust.request"), Checked: checked}},
	})
}

// importKinds lists the import kinds the adapter offers, DID first.
func importKinds(caps *backendv1.GetCapabilitiesResponse) []string {
	var out []string
	if has(caps, backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID) {
		out = append(out, kindDID)
	}
	if has(caps, backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509) {
		out = append(out, kindX509)
	}
	return out
}

// ownBlock is "Bring your own": a DID or an X.509 chain with the key
// reference in the key store of the stack.
func (p *Pages) ownBlock(b *blocks, v identityView, kinds []string, csrf template.HTML) template.HTML {
	kind := kinds[0]
	for _, k := range kinds {
		if k == v.kind {
			kind = k
		}
	}
	var tabs template.HTML
	if len(kinds) > 1 {
		links := make([]components.Link, 0, len(kinds))
		for _, k := range kinds {
			links = append(links, components.Link{Href: IdentityPath + "?kind=" + k + "#own", Text: msg.T("issuer.identity.tab." + k + ".label"), Current: k == kind})
		}
		tabs = b.add("tabs", components.Tabs{Label: msg.T("issuer.identity.tabs.label"), Links: links})
	}
	subject := b.add("field", components.Field{ID: "did", Label: msg.T("issuer.identity.did.label"), Value: v.form.Get("did"),
		Hint: msg.T("issuer.identity.did.hint"), Error: v.errs["did"], Autocomplete: "off"})
	if kind == kindX509 {
		subject = b.add("field", components.Field{ID: "chain", Label: msg.T("issuer.identity.chain.label"), Type: "textarea",
			Value: v.form.Get("chain"), Hint: msg.T("issuer.identity.chain.hint"), Error: v.errs["chain"]})
	}
	fields := components.Join(
		template.HTML(`<input type="hidden" name="kind" value="`+kind+`">`), //nolint:gosec // the kind is one of two constants
		subject,
		b.add("field", components.Field{ID: "key_reference", Label: msg.T("issuer.identity.key_reference.label"), Type: "textarea",
			Value: v.form.Get("key_reference"), Hint: msg.T("issuer.identity.key_reference.hint"), Error: v.errs["key_reference"]}),
		b.add("field", components.Field{ID: "display_name", Label: msg.T("issuer.identity.org.label"), Value: v.form.Get("display_name"),
			Autocomplete: "organization"}),
		b.add("field", components.Field{ID: "legal_identifier", Label: msg.T("issuer.identity.legal.label"), Value: v.form.Get("legal_identifier")}),
		p.trustChoice(b, v, "own-trust"),
		b.add("button", components.Button{Text: msg.T("issuer.identity.check.label"), Type: "submit", Name: "action", Value: "check"}),
		b.add("button", components.Button{Text: msg.T("issuer.identity.register.label"), Type: "submit", Variant: "primary", Name: "action", Value: "register"}),
	)
	var checked template.HTML
	if note := v.form.Get("checked"); note != "" {
		checked = b.add("note", components.Note{Label: msg.T("issuer.identity.check.label"), Text: note})
	}
	return b.add("block", components.Block{
		ID: "own", Title: msg.T("issuer.identity.own.label"), Lead: msg.T("issuer.identity.own.text"),
		Body: components.Join(tabs, checked, formHTML(IdentityPath+"import", csrf, fields)),
	})
}

// formHTML wraps fields in a POST form with the synchronizer token.
func formHTML(action string, csrf, fields template.HTML) template.HTML {
	return template.HTML(`<form method="post" action="`+template.HTMLEscapeString(action)+`">`) + csrf + fields + template.HTML(`</form>`) //nolint:gosec // the action is escaped and the parts come from the kit
}

// readForm parses a posted form with a bounded body.
func readForm(pg page) (url.Values, error) {
	pg.r.Body = http.MaxBytesReader(pg.w, pg.r.Body, MaxFormBytes)
	if err := pg.r.ParseForm(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return pg.r.PostForm, nil
}

// provision asks the stack for a new identity (ADR-046 decision 2).
func (p *Pages) provision(pg page) error {
	v := p.identityView(pg)
	if !has(v.caps, backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION) || p.opts.Identity == nil {
		return connect.NewError(connect.CodeNotFound, errors.New("the stack provisions no identity"))
	}
	f, err := readForm(pg)
	if err != nil {
		return err
	}
	v.form, v.errs = f, map[string]string{}
	method := f.Get("method")
	if !contains(v.caps.GetDidMethods(), method) {
		v.errs["method"] = msg.T("issuer.identity.error.method")
		return p.renderIdentity(pg, v)
	}
	ctx := pg.r.Context()
	res, err := p.opts.Identity.ProvisionIssuerIdentity(ctx, connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{
		Method: method, KeyType: f.Get("key_type"), Domain: p.host(),
	}))
	if err != nil {
		p.audit(ctx, ActionProvisionIdentity, method, err)
		v.toasts = []components.Toast{{Level: "bad", Text: msg.T("issuer.identity.error.stack")}}
		return p.renderIdentity(pg, v)
	}
	p.audit(ctx, ActionProvisionIdentity, firstIdentifier(res.Msg.GetIdentity()), nil)
	return p.afterChange(pg, v, res.Msg.GetIdentity(), "")
}

// host returns the host of the public URL of the pair, with its port.
func (p *Pages) host() string {
	u, err := url.Parse(p.opts.PublicURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// importIdentity checks a DID or a chain, and on "register" binds it to
// the key reference in the stack (ADR-046 decision 2).
func (p *Pages) importIdentity(pg page) error {
	v := p.identityView(pg)
	f, err := readForm(pg)
	if err != nil {
		return err
	}
	kind := f.Get("kind")
	if !contains(importKinds(v.caps), kind) || p.opts.Identity == nil {
		return connect.NewError(connect.CodeNotFound, errors.New("the stack imports no such identity"))
	}
	v.form, v.errs, v.kind = f, map[string]string{}, kind
	req := &backendv1.ImportIssuerIdentityRequest{
		KeyReference: strings.TrimSpace(f.Get("key_reference")), DisplayName: strings.TrimSpace(f.Get("display_name")),
		LegalIdentifier: strings.TrimSpace(f.Get("legal_identifier")),
	}
	var checked string
	if kind == kindDID {
		id := strings.TrimSpace(f.Get("did"))
		checked, v.errs["did"] = checkDID(id)
		req.Subject = &backendv1.ImportIssuerIdentityRequest_Did{Did: id}
	} else {
		chain := f.Get("chain")
		checked, v.errs["chain"] = checkChain(chain)
		req.Subject = &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: chain}
	}
	if req.KeyReference == "" || !json.Valid([]byte(req.KeyReference)) || !strings.HasPrefix(req.KeyReference, "{") {
		v.errs["key_reference"] = msg.T("issuer.identity.error.key_reference")
	}
	for k, e := range v.errs {
		if e == "" {
			delete(v.errs, k)
		}
	}
	if f.Get("action") == "check" || len(v.errs) > 0 {
		// The note names a good subject even when the key reference
		// still needs a fix.
		if checked != "" {
			v.form.Set("checked", checked)
		}
		return p.renderIdentity(pg, v)
	}
	ctx := pg.r.Context()
	res, err := p.opts.Identity.ImportIssuerIdentity(ctx, connect.NewRequest(req))
	if err != nil {
		p.audit(ctx, ActionImportIdentity, kind, err)
		v.toasts = []components.Toast{{Level: "bad", Text: msg.T("issuer.identity.error.stack")}}
		return p.renderIdentity(pg, v)
	}
	p.audit(ctx, ActionImportIdentity, firstIdentifier(res.Msg.GetIdentity()), nil)
	return p.afterChange(pg, v, res.Msg.GetIdentity(), strings.TrimSpace(f.Get("display_name")))
}

// checkDID checks a DID offline: did:key and did:jwk resolve here, and a
// did:web must name a host. It returns the note of a good DID or the
// error of a bad one.
func checkDID(id string) (string, string) {
	if _, err := did.Method(id); err != nil {
		return "", msg.T("issuer.identity.error.did")
	}
	var doc did.Document
	var err error
	switch {
	case strings.HasPrefix(id, "did:key:"):
		doc, err = did.KeyDocument(id)
	case strings.HasPrefix(id, "did:jwk:"):
		doc, err = did.JWKDocument(id)
	case strings.HasPrefix(id, "did:web:"):
		if _, err = did.WebURL(id); err != nil {
			return "", msg.T("issuer.identity.error.did")
		}
		return msg.T("issuer.identity.check.did", id), ""
	default:
		return msg.T("issuer.identity.check.did", id), ""
	}
	if err != nil {
		return "", msg.T("issuer.identity.error.resolve")
	}
	return msg.T("issuer.identity.check.resolved", id, strconv.Itoa(len(doc.VerificationMethod))), ""
}

// checkChain reads a PEM chain and names its leaf.
func checkChain(text string) (string, string) {
	rest := []byte(text)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil && block.Type == "CERTIFICATE" {
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return "", msg.T("issuer.identity.error.chain")
	}
	return msg.T("issuer.identity.check.x509", strconv.Itoa(len(certs)), certs[0].Subject.String()), ""
}

// firstIdentifier returns the first identifier of an identity, or "".
func firstIdentifier(id *backendv1.IssuerIdentity) string {
	if len(id.GetIdentifiers()) == 0 {
		return ""
	}
	return id.GetIdentifiers()[0]
}

// afterChange asks the trust registry for a pending entry when the box
// is on, then sends the browser to the status of the page.
func (p *Pages) afterChange(pg page, v identityView, id *backendv1.IssuerIdentity, name string) error {
	first := firstIdentifier(id)
	notices := []string{"registered"}
	if v.form.Get("trust") == "yes" && v.trustURL != "" && p.opts.Trust != nil && first != "" {
		notices = append(notices, p.requestTrust(pg.r.Context(), v.trustURL, first, name))
	}
	q := url.Values{"notice": {strings.Join(notices, ",")}, "id": {first}}
	http.Redirect(pg.w, pg.r, IdentityPath+"?"+q.Encode(), http.StatusSeeOther)
	return nil
}

// requestTrust writes a pending entry for the identity, unless the
// registry holds an entry that is not pending (P2-03). It returns the
// notice of the outcome.
func (p *Pages) requestTrust(ctx context.Context, registry, id, name string) string {
	client := p.opts.Trust(registry)
	got, err := client.GetEntry(ctx, staffshell.AsActor(ctx, &trustv1.GetEntryRequest{Identifier: trustIdentifier(id)}))
	switch {
	case err == nil && got.Msg.GetEntry().GetStatus() != trustv1.Status_STATUS_PENDING:
		return "trust_kept"
	case err != nil && connect.CodeOf(err) != connect.CodeNotFound:
		p.audit(ctx, ActionRequestTrust, id, err)
		return "trust_failed"
	}
	if name == "" {
		name = id
	}
	_, err = client.UpsertEntry(ctx, staffshell.AsActor(ctx, &trustv1.UpsertEntryRequest{Entry: &trustv1.TrustEntry{
		Identifier: trustIdentifier(id), DisplayName: name, Role: commonv1.Role_ROLE_ISSUER,
		Status: trustv1.Status_STATUS_PENDING, ServiceEndpoint: p.opts.PublicURL,
	}}))
	p.audit(ctx, ActionRequestTrust, id, err)
	if err != nil {
		return "trust_failed"
	}
	return "trust_requested"
}

// audit writes one event of the identity page with the staff member as
// the actor. A failure names the Connect code only (ADR-039 decision 3).
func (p *Pages) audit(ctx context.Context, action, target string, err error) {
	p.opts.Audit.Record(auditlog.WithActor(ctx, staffshell.Actor(ctx)), nil, action, target, "", err)
}

// didDocument serves the DID document of a did:web of the host of the
// pair, so the identity the stack signs with resolves (ADR-046). Any
// other identity gives 404.
func (p *Pages) didDocument(w http.ResponseWriter, r *http.Request) {
	if p.opts.Identity == nil {
		http.NotFound(w, r)
		return
	}
	res, err := p.opts.Identity.GetIssuerIdentity(r.Context(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	want := "did:web:" + strings.ReplaceAll(p.host(), ":", "%3A")
	if err != nil || firstIdentifier(res.Msg.GetIdentity()) != want || res.Msg.GetIdentity().GetDidDocument() == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	w.Header().Set("Cache-Control", "max-age=300")
	if _, err := w.Write([]byte(res.Msg.GetIdentity().GetDidDocument())); err != nil {
		return
	}
}

// DIDDocument returns the handler of DIDDocumentPath. It needs no
// session: a verifier resolves the DID.
func (p *Pages) DIDDocument() http.Handler { return http.HandlerFunc(p.didDocument) }

// contains reports whether list holds v.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
