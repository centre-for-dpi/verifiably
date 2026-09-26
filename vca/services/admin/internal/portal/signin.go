// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The holder authorization server of an issuer stack keeps a provider
// registry of its own (ADR-052 decision 2). The admin adds, edits, turns
// off and removes its holder providers here, through the provider RPCs
// of the adapter on the compose network, with the admin session. The
// server binds an offer or finds a holder only on a claim the provider
// vouches for (ADR-056 decision 2).

// maxVerifiedClaims caps the claims one provider lists.
const maxVerifiedClaims = 16

// registerHolders adds the pages of the holder providers.
func (p *Portal) registerHolders(mux *http.ServeMux) {
	// The pages sit under the providers page, so its entry of the side
	// navigation stays current. A create posts to the path of its form,
	// since a shorter path would overlap the routes of that page.
	at := p.opts.Prefix + "/providers/holders/{pair}"
	mux.HandleFunc("GET "+at+"/new", p.guarded(p.newHolder))
	mux.HandleFunc("POST "+at+"/new", p.posted(p.createHolder))
	mux.HandleFunc("GET "+at+"/{id}", p.guarded(p.editHolder))
	mux.HandleFunc("POST "+at+"/{id}", p.posted(p.updateHolder))
	mux.HandleFunc("POST "+at+"/{id}/enable", p.posted(p.toggleHolder))
	mux.HandleFunc("POST "+at+"/{id}/delete", p.posted(p.deleteHolder))
}

// signInTarget is one live issuer pair whose adapter runs a holder
// authorization server.
type signInTarget struct {
	pair    string
	name    string
	adapter string
}

// signInTargets lists the live issuer pairs whose adapter lists
// FEATURE_HOLDER_SIGN_IN_SOURCE, in snapshot order.
func signInTargets(f frame) []signInTarget {
	var out []signInTarget
	for _, st := range f.snap.Live() {
		peer := st.Peer
		if peer.Role != commonv1.Role_ROLE_ISSUER || peer.Adapter() == "" || !st.Has(backendv1.Feature_FEATURE_HOLDER_SIGN_IN_SOURCE) {
			continue
		}
		out = append(out, signInTarget{pair: peer.Pair, name: f.snap.StackName(peer.Dpg), adapter: peer.Adapter()})
	}
	return out
}

// holderTarget returns the target of the pair in the path, or a not
// found error.
func (p *Portal) holderTarget(r *http.Request) (signInTarget, error) {
	for _, t := range signInTargets(p.frame(r.Context())) {
		if t.pair == r.PathValue("pair") {
			return t, nil
		}
	}
	return signInTarget{}, connect.NewError(connect.CodeNotFound, errors.New("portal: the pair runs no holder authorization server"))
}

// signInClient returns the provider RPC client of an adapter.
func (p *Portal) signInClient(adapter string) adminv1connect.AdminServiceClient {
	client := p.opts.PeerClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return adminv1connect.NewAdminServiceClient(client, adapter)
}

// signInBlock draws the card of the holder providers: one table per
// holder authorization server, with its providers and their actions.
func (p *Portal) signInBlock(ctx context.Context, b *blocks, f frame, s session) template.HTML {
	targets := signInTargets(f)
	if len(targets) == 0 {
		return ""
	}
	parts := make([]template.HTML, 0, 2*len(targets))
	for _, target := range targets {
		base := p.opts.Prefix + "/providers/holders/" + target.pair
		add := b.add("button", components.Button{Text: msg.T("admin.holders.add.label"), Href: base + "/new"})
		res, err := p.signInClient(target.adapter).ListAuthProviders(ctx, call(s, &adminv1.ListAuthProvidersRequest{}))
		if err != nil {
			parts = append(parts, b.add("note", components.Note{Label: target.name, Text: msg.T("admin.signin.down")}))
			continue
		}
		rows := make([]components.Row, 0, len(res.Msg.GetProviders()))
		for _, m := range res.Msg.GetProviders() {
			rows = append(rows, p.holderRow(b, base, oidcflow.FromAdminProto(m), s.CSRF))
		}
		parts = append(parts, b.add("table", components.Table{
			ID: "holders-" + target.pair, Caption: msg.T("admin.holders.caption.label", target.name),
			Columns: []string{
				msg.T("admin.providers.column.provider.label"), msg.T("admin.providers.column.realm.label"),
				msg.T("admin.holders.column.auth.label"), msg.T("admin.signin.column.claims.label"),
				msg.T("admin.providers.column.state.label"), msg.T("admin.providers.column.actions.label"),
			},
			Rows: rows, Empty: msg.T("admin.holders.empty"),
		}), add)
	}
	return b.add("card", components.Card{
		ID: "holder-providers", Title: msg.T("admin.holders.title.label"), Text: msg.T("admin.holders.lead"), Body: components.Join(parts...),
	})
}

// holderRow is one row of a holder provider table: the provider (a link
// to its form), its realm or issuer, its client authentication, its
// verified claims, its state with the default flag, and the actions.
func (p *Portal) holderRow(b *blocks, base string, pr oidcflow.Provider, csrf string) components.Row {
	state := components.Badge{Status: "warn", Text: msg.T("admin.providers.disabled.label")}
	toggle := components.Button{Text: msg.T("admin.providers.enable.label"), Type: "submit"}
	next := "true"
	if pr.Enabled {
		state = components.Badge{Status: "ok", Text: msg.T("admin.providers.enabled.label")}
		toggle = components.Button{Text: msg.T("admin.providers.disable.label"), Type: "submit"}
		next = "false"
	}
	badges := b.add("badge", state)
	if pr.IsDefault {
		badges = components.Join(badges, template.HTML(" "), b.add("badge", components.Badge{Status: "info", Text: msg.T("admin.providers.default.label")}))
	}
	at := base + "/" + pr.ID
	actions := components.Join(
		template.HTML(`<div class="row-actions">`), //nolint:gosec // a literal wrapper
		form(at+"/enable", csrf,
			template.HTML(`<input type="hidden" name="enabled" value="`+next+`">`), //nolint:gosec // a literal value
			b.add("button", toggle)),
		form(at+"/delete", csrf,
			b.add("button", components.Button{Text: msg.T("admin.providers.remove.label"), Type: "submit", Variant: "danger"})),
		template.HTML(`</div>`),
	)
	name := template.HTML(`<a href="` + template.HTMLEscapeString(at) + `">` + //nolint:gosec // both parts are escaped
		template.HTMLEscapeString(pr.DisplayName) + `</a>`)
	claims := strings.Join(pr.VerifiedClaims, ", ")
	if claims == "" {
		claims = msg.T("admin.holders.claims.standard.label")
	}
	return components.Row{
		{HTML: name},
		{Text: realmOrIssuer(pr)},
		{Text: holderAuthLabel(pr.EffectiveTokenAuth())},
		{Text: claims},
		{HTML: badges},
		{HTML: actions},
	}
}

// holderMethods are the client authentication methods of the form, in
// form order.
var holderMethods = []oidcflow.TokenAuth{
	oidcflow.TokenAuthNone, oidcflow.TokenAuthClientSecretBasic, oidcflow.TokenAuthClientSecretPost, oidcflow.TokenAuthPrivateKeyJWT,
}

// holderAuthLabel names a client authentication method.
func holderAuthLabel(m oidcflow.TokenAuth) string {
	return msg.T("admin.holders.auth." + string(m) + ".label")
}

// holderInput is what the holder provider form posts.
type holderInput struct {
	Kind           string
	DisplayName    string
	DiscoveryURL   string
	ClientID       string
	TokenAuth      string
	SecretStore    string
	SecretName     string
	VerifiedClaims string
	IsDefault      bool
}

// readHolderInput reads the form of a request.
func readHolderInput(r *http.Request) holderInput {
	get := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return holderInput{
		Kind: get("kind"), DisplayName: get("display_name"), DiscoveryURL: get("discovery_url"), ClientID: get("client_id"),
		TokenAuth: get("token_auth"), SecretStore: get("secret_store"), SecretName: get("secret_name"),
		VerifiedClaims: r.PostFormValue("verified_claims"), IsDefault: get("is_default") == "true",
	}
}

// holderInputOf fills the form from a stored record. The reference
// stays empty: the form never echoes it (ADR-015).
func holderInputOf(pr oidcflow.Provider) holderInput {
	store := pr.PrivateKey.Store
	if pr.EffectiveTokenAuth() != oidcflow.TokenAuthPrivateKeyJWT {
		store = pr.ClientSecret.Store
	}
	kind := string(pr.Kind)
	if kind == "" {
		kind = string(oidcflow.KindGeneric)
	}
	return holderInput{
		Kind: kind, DisplayName: pr.DisplayName, DiscoveryURL: pr.DiscoveryURL, ClientID: pr.ClientID,
		TokenAuth: string(pr.EffectiveTokenAuth()), SecretStore: string(store),
		VerifiedClaims: strings.Join(pr.VerifiedClaims, ", "), IsDefault: pr.IsDefault,
	}
}

// invalid is a form error of the holder provider form.
func invalid(key string) error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(msg.T(key)))
}

// record builds the provider of the form. current, when set, is the
// record under edit: its id and state stay, and so does its reference
// when the form names none and the method still needs the same kind of
// reference.
func (in holderInput) record(current *oidcflow.Provider) (*adminv1.AuthProvider, error) {
	if in.DisplayName == "" || in.ClientID == "" || in.DiscoveryURL == "" {
		return nil, invalid("admin.holders.error.required")
	}
	claims, err := parseClaims(in.VerifiedClaims)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	method := oidcflow.TokenAuth(in.TokenAuth)
	if !containsMethod(method) {
		return nil, invalid("admin.holders.error.method")
	}
	pr := oidcflow.Provider{
		DisplayName: in.DisplayName, DiscoveryURL: onboard.DiscoveryURL(in.DiscoveryURL), ClientID: in.ClientID,
		Enabled: true, Roles: []string{"holder"},
		Profile: oidcflow.Profile{TokenAuthMethod: method, VerifiedClaims: claims, IsDefault: in.IsDefault},
	}
	var ref oidcflow.SecretRef
	if in.SecretName != "" {
		store := oidcflow.SecretStore(in.SecretStore)
		if store != oidcflow.SecretEnv && store != oidcflow.SecretFile {
			return nil, invalid("admin.holders.error.store")
		}
		ref = oidcflow.SecretRef{Store: store, Name: in.SecretName}
	}
	if current != nil {
		pr.ID, pr.Enabled = current.ID, current.Enabled
		if ref.IsZero() && method == oidcflow.TokenAuthPrivateKeyJWT {
			ref = current.PrivateKey
		} else if ref.IsZero() {
			ref = current.ClientSecret
		}
	}
	switch method {
	case oidcflow.TokenAuthPrivateKeyJWT:
		pr.PrivateKey = ref
	case oidcflow.TokenAuthClientSecretBasic, oidcflow.TokenAuthClientSecretPost:
		pr.ClientSecret = ref
	}
	if method != oidcflow.TokenAuthNone && ref.IsZero() {
		return nil, invalid("admin.holders.error.reference")
	}
	preset, _ := onboard.PresetFor(oidcflow.Kind(in.Kind))
	preset.Apply(&pr)
	// A holder sign in maps no roles, and the message carries no scopes.
	pr.RolesClaimPath, pr.Scopes = "", nil
	return oidcflow.ToAdminProto(pr), nil
}

func containsMethod(m oidcflow.TokenAuth) bool {
	for _, known := range holderMethods {
		if m == known {
			return true
		}
	}
	return false
}

// newHolder renders the empty form of a holder provider.
func (p *Portal) newHolder(w http.ResponseWriter, r *http.Request, s session) error {
	target, err := p.holderTarget(r)
	if err != nil {
		return err
	}
	in := holderInput{Kind: string(oidcflow.KindKeycloak), TokenAuth: string(oidcflow.TokenAuthNone), SecretStore: string(oidcflow.SecretEnv)}
	return p.holderPage(w, r, s, target, in, nil)
}

// editHolder renders the form of one holder provider.
func (p *Portal) editHolder(w http.ResponseWriter, r *http.Request, s session) error {
	target, err := p.holderTarget(r)
	if err != nil {
		return err
	}
	current, err := p.holder(r, s, target)
	if err != nil {
		return err
	}
	return p.holderPage(w, r, s, target, holderInputOf(current), &current)
}

// holder reads the record of the path from the adapter.
func (p *Portal) holder(r *http.Request, s session, target signInTarget) (oidcflow.Provider, error) {
	got, err := p.signInClient(target.adapter).GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return oidcflow.Provider{}, err
	}
	return oidcflow.FromAdminProto(got.Msg.GetProvider()), nil
}

// holderPage renders the form of a holder provider.
func (p *Portal) holderPage(w http.ResponseWriter, r *http.Request, s session, target signInTarget, in holderInput, current *oidcflow.Provider) error {
	f := p.frame(r.Context())
	b := p.blocks()
	action := p.opts.Prefix + "/providers/holders/" + target.pair + "/new"
	title := msg.T("admin.holders.new.label")
	if current != nil {
		action = p.opts.Prefix + "/providers/holders/" + target.pair + "/" + current.ID
		title = msg.T("admin.holders.edit.label")
	}
	content := p.holderForm(b, action, in, current, s.CSRF)
	if b.err != nil {
		return b.err
	}
	lead := msg.T("admin.holders.form.lead", target.name)
	return p.renderWith(w, r, s, f, components.Page{
		Title: title, Lead: lead, Description: lead, Content: content,
	})
}

// holderForm draws the form: the kind, the name, the discovery URL, the
// client, its authentication and reference, the verified claims, and
// the default flag.
func (p *Portal) holderForm(b *blocks, action string, in holderInput, current *oidcflow.Provider, csrf string) template.HTML {
	kinds := make([]components.Option, 0, 4)
	for _, preset := range onboard.Presets() {
		kinds = append(kinds, components.Option{Value: string(preset.Kind), Text: preset.Label, Selected: string(preset.Kind) == in.Kind})
	}
	methods := make([]components.Option, 0, len(holderMethods))
	for _, m := range holderMethods {
		methods = append(methods, components.Option{Value: string(m), Text: holderAuthLabel(m), Selected: string(m) == in.TokenAuth})
	}
	stores := []components.Option{
		{Value: string(oidcflow.SecretEnv), Text: msg.T("admin.holders.store.env.label"), Selected: in.SecretStore != string(oidcflow.SecretFile)},
		{Value: string(oidcflow.SecretFile), Text: msg.T("admin.holders.store.file.label"), Selected: in.SecretStore == string(oidcflow.SecretFile)},
	}
	refHint := msg.T("admin.holders.reference.hint")
	if current != nil && (!current.ClientSecret.IsZero() || !current.PrivateKey.IsZero()) {
		refHint = msg.T("admin.holders.reference.kept")
	}
	fields := components.Join(
		b.add("field", components.Field{ID: "kind", Label: msg.T("admin.providers.kind.label"), Type: "select", Options: kinds, Hint: msg.T("admin.holders.kind.hint")}),
		b.add("field", components.Field{ID: "display_name", Label: msg.T("admin.providers.display_name.label"), Value: in.DisplayName, Required: true}),
		b.add("field", components.Field{ID: "discovery_url", Label: msg.T("admin.holders.discovery.label"), Value: in.DiscoveryURL, Required: true, Type: "url", Hint: msg.T("admin.holders.discovery.hint")}),
		b.add("field", components.Field{ID: "client_id", Label: msg.T("admin.providers.client_id.label"), Value: in.ClientID, Required: true, Autocomplete: "off"}),
		b.add("field", components.Field{ID: "token_auth", Label: msg.T("admin.holders.column.auth.label"), Type: "select", Options: methods, Hint: msg.T("admin.holders.auth.hint")}),
		b.add("field", components.Field{ID: "secret_store", Label: msg.T("admin.holders.store.label"), Type: "select", Options: stores}),
		b.add("field", components.Field{ID: "secret_name", Label: msg.T("admin.holders.reference.label"), Hint: refHint, Autocomplete: "off"}),
		b.add("field", components.Field{
			ID: "verified_claims", Label: msg.T("admin.signin.column.claims.label"), Value: in.VerifiedClaims,
			Hint: msg.T("admin.signin.claims.hint"), Attrs: map[string]string{"maxlength": "500"}, Autocomplete: "off",
		}),
		b.add("choice", components.Choice{ID: "is_default", Legend: msg.T("admin.providers.column.default.label"), Multiple: true, Options: []components.ChoiceOption{
			{Value: "true", Title: msg.T("admin.holders.default.option.label"), Text: msg.T("admin.holders.default.text"), Checked: in.IsDefault},
		}}),
		template.HTML(`<div class="form-actions">`), //nolint:gosec // a literal wrapper
		b.add("button", components.Button{Text: msg.T("admin.holders.back.label"), Href: p.opts.Prefix + "/providers"}),
		b.add("button", components.Button{Text: msg.T("admin.providers.save.label"), Type: "submit", Variant: "primary"}),
		template.HTML(`</div>`),
	)
	return b.add("card", components.Card{
		ID: "holder-form", Title: msg.T("admin.providers.details.label"),
		Body: stackedForm(action, csrf, fields),
	})
}

// createHolder adds a holder provider at the adapter.
func (p *Portal) createHolder(w http.ResponseWriter, r *http.Request, s session) error {
	target, err := p.holderTarget(r)
	if err != nil {
		return err
	}
	record, err := readHolderInput(r).record(nil)
	if err != nil {
		return err
	}
	if _, err := p.signInClient(target.adapter).CreateAuthProvider(r.Context(), call(s, &adminv1.CreateAuthProviderRequest{Provider: record})); err != nil {
		return err
	}
	return p.providersPage(w, r, s, notice("holder-provider-added"))
}

// updateHolder saves the changes of one holder provider.
func (p *Portal) updateHolder(w http.ResponseWriter, r *http.Request, s session) error {
	target, err := p.holderTarget(r)
	if err != nil {
		return err
	}
	current, err := p.holder(r, s, target)
	if err != nil {
		return err
	}
	record, err := readHolderInput(r).record(&current)
	if err != nil {
		return err
	}
	if _, err := p.signInClient(target.adapter).UpdateAuthProvider(r.Context(), call(s, &adminv1.UpdateAuthProviderRequest{Provider: record})); err != nil {
		return err
	}
	return p.providersPage(w, r, s, notice("holder-provider-saved"))
}

// toggleHolder turns one holder provider on or off.
func (p *Portal) toggleHolder(w http.ResponseWriter, r *http.Request, s session) error {
	target, err := p.holderTarget(r)
	if err != nil {
		return err
	}
	client := p.signInClient(target.adapter)
	got, err := client.GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	record := got.Msg.GetProvider()
	record.Enabled = r.PostFormValue("enabled") == "true"
	if _, err := client.UpdateAuthProvider(r.Context(), call(s, &adminv1.UpdateAuthProviderRequest{Provider: record})); err != nil {
		return err
	}
	code := "holder-provider-disabled"
	if record.GetEnabled() {
		code = "holder-provider-enabled"
	}
	p.redirect(w, r, "/providers", code)
	return nil
}

// deleteHolder removes one holder provider.
func (p *Portal) deleteHolder(w http.ResponseWriter, r *http.Request, s session) error {
	target, err := p.holderTarget(r)
	if err != nil {
		return err
	}
	if _, err := p.signInClient(target.adapter).DeleteAuthProvider(r.Context(), call(s, &adminv1.DeleteAuthProviderRequest{Id: r.PathValue("id")})); err != nil {
		return err
	}
	p.redirect(w, r, "/providers", "holder-provider-removed")
	return nil
}

// parseClaims reads a comma separated list of claim names. A name holds
// letters, digits, and the characters _ . - only.
func parseClaims(text string) ([]string, error) {
	var out []string
	for _, c := range strings.Split(text, ",") {
		c = strings.TrimSpace(c)
		if c == "" || containsName(out, c) {
			continue
		}
		for _, ch := range c {
			ok := ch == '_' || ch == '.' || ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
			if !ok || len(c) > 64 {
				return nil, errors.New("portal: a claim name holds letters, digits, and _ . - only")
			}
		}
		out = append(out, c)
	}
	if len(out) > maxVerifiedClaims {
		return nil, errors.New("portal: too many claims")
	}
	return out, nil
}

func containsName(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
