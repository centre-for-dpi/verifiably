// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// formRoles are the roles the provider form offers, in form order.
var formRoles = []string{"admin", "issuer", "holder", "verifier"}

// registerProviders adds the login provider pages (board Admin-Providers,
// ADR-035 decisions 2, 4 and 5).
func (p *Portal) registerProviders(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/providers", p.guarded(p.providers))
	mux.HandleFunc("GET "+at+"/providers/new", p.guarded(p.newProvider))
	mux.HandleFunc("POST "+at+"/providers", p.posted(p.createProvider))
	mux.HandleFunc("POST "+at+"/providers/test", p.posted(p.testDiscovery))
	mux.HandleFunc("GET "+at+"/providers/{id}", p.guarded(p.editProvider))
	mux.HandleFunc("POST "+at+"/providers/{id}", p.posted(p.updateProvider))
	mux.HandleFunc("POST "+at+"/providers/{id}/enable", p.posted(p.toggleProvider))
	mux.HandleFunc("POST "+at+"/providers/{id}/delete", p.posted(p.deleteProvider))
}

// providers renders the provider table with its row actions.
func (p *Portal) providers(w http.ResponseWriter, r *http.Request, s session) error {
	return p.providersPage(w, r, s, notice(r.URL.Query().Get("notice")))
}

// providersPage renders the table with the given toasts.
func (p *Portal) providersPage(w http.ResponseWriter, r *http.Request, s session, toasts []components.Toast) error {
	res, err := p.opts.Client.ListAuthProviders(r.Context(), call(s, &adminv1.ListAuthProvidersRequest{
		Page: &commonv1.Pagination{PageSize: 500},
	}))
	if err != nil {
		return err
	}
	f := p.frame(r.Context())
	b := p.blocks()
	at := p.opts.Prefix
	add := b.add("button", components.Button{Text: msg.T("admin.providers.add.label"), Href: at + "/providers/new", Variant: "primary"})
	var content template.HTML
	if len(res.Msg.GetProviders()) == 0 {
		content = b.add("empty", components.Empty{
			Title: msg.T("admin.providers.empty.title"), Text: msg.T("admin.providers.empty.text"),
			Action: components.Button{Text: msg.T("admin.providers.add.label"), Href: at + "/providers/new", Variant: "primary"},
		})
	} else {
		rows := make([]components.Row, 0, len(res.Msg.GetProviders()))
		for _, m := range res.Msg.GetProviders() {
			rows = append(rows, p.providerRow(b, f, oidcflow.FromAdminProto(m), s.CSRF))
		}
		content = b.add("table", components.Table{
			ID: "providers", Caption: msg.T("admin.providers.caption.label", strconv.Itoa(len(rows))),
			Columns: []string{
				msg.T("admin.providers.column.provider.label"), msg.T("admin.providers.column.realm.label"),
				msg.T("admin.providers.column.roles.label"), msg.T("admin.providers.column.stacks.label"),
				msg.T("admin.providers.column.state.label"), msg.T("admin.providers.column.default.label"),
				msg.T("admin.providers.column.actions.label"),
			},
			Rows: rows,
		})
	}
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       msg.T("admin.nav.providers.label"),
		Lead:        msg.T("admin.providers.lead"),
		Actions:     add,
		Description: msg.T("admin.providers.lead"),
		Content:     content,
		Toasts:      toasts,
	})
}

// providerRow is one row of the table: the provider (a link to its edit
// form), its realm or issuer, its roles, its stacks, its state, the
// default flag, and the actions.
func (p *Portal) providerRow(b *blocks, f frame, pr oidcflow.Provider, csrf string) components.Row {
	at := p.opts.Prefix
	state := components.Badge{Status: "warn", Text: msg.T("admin.providers.disabled.label")}
	toggle := components.Button{Text: msg.T("admin.providers.enable.label"), Type: "submit"}
	next := "true"
	if pr.Enabled {
		state = components.Badge{Status: "ok", Text: msg.T("admin.providers.enabled.label")}
		toggle = components.Button{Text: msg.T("admin.providers.disable.label"), Type: "submit"}
		next = "false"
	}
	var isDefault template.HTML
	if pr.IsDefault {
		isDefault = b.add("badge", components.Badge{Status: "info", Text: msg.T("admin.providers.default.label")})
	}
	actions := components.Join(
		template.HTML(`<div class="row-actions">`), //nolint:gosec // a literal wrapper
		form(at+"/providers/"+pr.ID+"/enable", csrf,
			template.HTML(`<input type="hidden" name="enabled" value="`+next+`">`), //nolint:gosec // a literal value
			b.add("button", toggle)),
		form(at+"/providers/"+pr.ID+"/delete", csrf,
			b.add("button", components.Button{Text: msg.T("admin.providers.remove.label"), Type: "submit", Variant: "danger"})),
		template.HTML(`</div>`),
	)
	// The name opens the edit form, so the row keeps two buttons.
	name := template.HTML(`<a href="` + template.HTMLEscapeString(at+"/providers/"+pr.ID) + `">` + //nolint:gosec // both parts are escaped
		template.HTMLEscapeString(pr.DisplayName) + `</a>`)
	return components.Row{
		{HTML: name},
		{Text: realmOrIssuer(pr)},
		{Text: roleLabels(pr.Roles)},
		{Text: stackLabels(f, pr.Stacks)},
		{HTML: b.add("badge", state)},
		{HTML: isDefault},
		{HTML: actions},
	}
}

// realmOrIssuer returns the realm label of a record, or its issuer.
func realmOrIssuer(pr oidcflow.Provider) string {
	if pr.Realm != "" {
		return pr.Realm
	}
	return issuerOf(pr.DiscoveryURL)
}

// issuerOf returns the issuer of a discovery URL: the URL without its
// well known path.
func issuerOf(discoveryURL string) string {
	if i := strings.Index(discoveryURL, "/.well-known/"); i >= 0 {
		return discoveryURL[:i]
	}
	return strings.TrimRight(discoveryURL, "/")
}

// roleLabels joins the labels of the roles of a record in form order.
func roleLabels(roles []string) string {
	var out []string
	for _, r := range formRoles {
		if hasName(roles, r) {
			out = append(out, msg.T("role."+r+".label"))
		}
	}
	return strings.Join(out, ", ")
}

// stackLabels joins the stack names of a record, or says every stack.
func stackLabels(f frame, stacks []string) string {
	if len(stacks) == 0 {
		return msg.T("admin.providers.all_stacks.label")
	}
	out := make([]string, 0, len(stacks))
	for _, id := range stacks {
		out = append(out, stackName(f.snap, configv1.Dpg(configv1.Dpg_value["DPG_"+strings.ToUpper(id)])))
	}
	return strings.Join(out, ", ")
}

// hasName reports whether list holds want.
func hasName(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// stackOption is one stack the form offers.
type stackOption struct {
	ID   string
	Name string
}

// presentStacks lists the stacks with at least one present pair, in
// enum order, with their display names.
func presentStacks(f frame) []stackOption {
	seen := map[configv1.Dpg]bool{}
	for _, st := range f.snap.Peers {
		if st.State != topology.Absent {
			seen[st.Peer.Dpg] = true
		}
	}
	var out []stackOption
	for d := range seen {
		out = append(out, stackOption{ID: shortName(d.String()), Name: stackName(f.snap, d)})
	}
	sort.Slice(out, func(i, j int) bool {
		return configv1.Dpg_value["DPG_"+strings.ToUpper(out[i].ID)] < configv1.Dpg_value["DPG_"+strings.ToUpper(out[j].ID)]
	})
	return out
}

// providerInput is what the provider form posts.
type providerInput struct {
	Kind            string
	DisplayName     string
	Issuer          string
	Client          string
	ClientID        string
	ClientSecretEnv string
	PrivateKeyEnv   string
	TokenAuth       string
	Register        string
	RolesClaimPath  string
	Roles           []string
	Stacks          []string
}

// readProviderInput reads the form of a request.
func readProviderInput(r *http.Request) providerInput {
	get := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return providerInput{
		Kind: get("kind"), DisplayName: get("display_name"), Issuer: get("issuer"), Client: get("client"),
		ClientID: get("client_id"), ClientSecretEnv: get("client_secret_env"), PrivateKeyEnv: get("private_key_env"),
		TokenAuth: get("token_auth"), Register: get("register"), RolesClaimPath: get("roles_claim_path"),
		Roles: r.PostForm["roles"], Stacks: r.PostForm["stacks"],
	}
}

// inputOf fills the form from a stored record. The secret references
// stay empty: the form never echoes them (ADR-015).
func inputOf(pr oidcflow.Provider) providerInput {
	kind := string(pr.Kind)
	if kind == "" {
		kind = string(oidcflow.KindGeneric)
	}
	return providerInput{
		Kind: kind, DisplayName: pr.DisplayName, Issuer: issuerOf(pr.DiscoveryURL), Client: "given",
		ClientID: pr.ClientID, TokenAuth: string(pr.TokenAuthMethod), Register: string(pr.Registration),
		RolesClaimPath: pr.RolesClaimPath, Roles: pr.Roles, Stacks: pr.Stacks,
	}
}

// record builds the provider message of the form. The preset of the kind
// fills what the operator left empty. current, when set, is the record
// under edit: its id, its default flag, and its secret references stay
// when the form names none.
func (in providerInput) record(current *oidcflow.Provider) (*adminv1.AuthProvider, bool) {
	pr := oidcflow.Provider{
		DisplayName:    in.DisplayName,
		DiscoveryURL:   onboard.DiscoveryURL(in.Issuer),
		ClientID:       in.ClientID,
		RolesClaimPath: in.RolesClaimPath,
		Enabled:        true,
		Profile: oidcflow.Profile{
			Registration:    oidcflow.Registration(in.Register),
			TokenAuthMethod: oidcflow.TokenAuth(in.TokenAuth),
		},
	}
	for _, r := range formRoles {
		if hasName(in.Roles, r) {
			pr.Roles = append(pr.Roles, r)
		}
	}
	for _, s := range in.Stacks {
		if configv1.Dpg_value["DPG_"+strings.ToUpper(s)] != 0 {
			pr.Stacks = append(pr.Stacks, strings.ToLower(s))
		}
	}
	if in.ClientSecretEnv != "" {
		pr.ClientSecret = oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: in.ClientSecretEnv}
	}
	if in.PrivateKeyEnv != "" {
		pr.PrivateKey = oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: in.PrivateKeyEnv}
	}
	if current != nil {
		pr.ID = current.ID
		pr.Enabled = current.Enabled
		pr.IsDefault = current.IsDefault
		pr.Realm = current.Realm
		pr.ConsoleURL = current.ConsoleURL
		if pr.ClientSecret.IsZero() {
			pr.ClientSecret = current.ClientSecret
		}
		if pr.PrivateKey.IsZero() {
			pr.PrivateKey = current.PrivateKey
		}
	}
	preset, _ := onboard.PresetFor(oidcflow.Kind(in.Kind))
	preset.Apply(&pr)
	return oidcflow.ToAdminProto(pr), in.Client == "dynamic"
}

// newProvider renders the empty form.
func (p *Portal) newProvider(w http.ResponseWriter, r *http.Request, s session) error {
	return p.formPage(w, r, s, providerInput{Kind: string(oidcflow.KindKeycloak), Client: "given"}, nil, "")
}

// editProvider renders the form of one record.
func (p *Portal) editProvider(w http.ResponseWriter, r *http.Request, s session) error {
	res, err := p.opts.Client.GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	current := oidcflow.FromAdminProto(res.Msg.GetProvider())
	return p.formPage(w, r, s, inputOf(current), &current, "")
}

// formPage renders the provider form with the typed values, and the
// discovery result when the test action produced one.
func (p *Portal) formPage(w http.ResponseWriter, r *http.Request, s session, in providerInput, current *oidcflow.Provider, result template.HTML) error {
	f := p.frame(r.Context())
	b := p.blocks()
	action := p.opts.Prefix + "/providers"
	title := msg.T("admin.providers.new.label")
	if current != nil {
		action += "/" + current.ID
		title = msg.T("admin.providers.edit.label")
	}
	content := p.providerForm(b, f, action, in, current, s.CSRF, result)
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       title,
		Lead:        msg.T("admin.providers.lead"),
		Description: msg.T("admin.providers.lead"),
		Content:     content,
	})
}

// providerForm draws the form: the kind preset, the issuer, the client,
// the secret references, the token method, the register action, the
// roles, the stacks, and the two actions.
func (p *Portal) providerForm(b *blocks, f frame, action string, in providerInput, current *oidcflow.Provider, csrf string, result template.HTML) template.HTML {
	kinds := make([]components.Option, 0, 4)
	for _, preset := range onboard.Presets() {
		kinds = append(kinds, components.Option{Value: string(preset.Kind), Text: preset.Label, Selected: string(preset.Kind) == in.Kind})
	}
	secretHint := msg.T("admin.providers.client_secret.hint")
	if current != nil && !current.ClientSecret.IsZero() {
		secretHint = msg.T("admin.providers.client_secret.kept")
	}
	keyHint := msg.T("admin.providers.private_key.hint")
	if current != nil && !current.PrivateKey.IsZero() {
		keyHint = msg.T("admin.providers.client_secret.kept")
	}
	roles := make([]components.ChoiceOption, 0, len(formRoles))
	for _, r := range formRoles {
		roles = append(roles, components.ChoiceOption{Value: r, Title: msg.T("role." + r + ".label"), Checked: hasName(in.Roles, r)})
	}
	var stacks template.HTML
	if present := presentStacks(f); len(present) > 0 {
		opts := make([]components.ChoiceOption, 0, len(present))
		for _, st := range present {
			opts = append(opts, components.ChoiceOption{Value: st.ID, Title: st.Name, Checked: hasName(in.Stacks, st.ID)})
		}
		stacks = b.add("choice", components.Choice{ID: "stacks", Legend: msg.T("admin.providers.stacks.label"), Hint: msg.T("admin.providers.stacks.hint"), Options: opts, Multiple: true})
	}
	testPath := p.opts.Prefix + "/providers/test"
	fields := components.Join(
		b.add("field", components.Field{ID: "kind", Label: msg.T("admin.providers.kind.label"), Type: "select", Options: kinds, Hint: msg.T("admin.providers.kind.hint")}),
		b.add("field", components.Field{ID: "display_name", Label: msg.T("admin.providers.display_name.label"), Value: in.DisplayName, Required: true}),
		b.add("field", components.Field{ID: "issuer", Label: msg.T("admin.providers.issuer.label"), Value: in.Issuer, Required: true, Type: "url", Hint: msg.T("admin.providers.issuer.hint")}),
		b.add("field", components.Field{ID: "client", Label: msg.T("admin.providers.client.label"), Type: "select", Options: []components.Option{
			{Value: "given", Text: msg.T("admin.providers.client.given.label"), Selected: in.Client != "dynamic"},
			{Value: "dynamic", Text: msg.T("admin.providers.client.dynamic.label"), Selected: in.Client == "dynamic"},
		}}),
		b.add("field", components.Field{ID: "client_id", Label: msg.T("admin.providers.client_id.label"), Value: in.ClientID}),
		b.add("field", components.Field{ID: "client_secret_env", Label: msg.T("admin.providers.client_secret.label"), Hint: secretHint}),
		b.add("field", components.Field{ID: "private_key_env", Label: msg.T("admin.providers.private_key.label"), Hint: keyHint}),
		b.add("field", components.Field{ID: "token_auth", Label: msg.T("admin.providers.token_auth.label"), Type: "select", Options: tokenAuthOptions(in.TokenAuth)}),
		b.add("field", components.Field{ID: "register", Label: msg.T("admin.providers.register.label"), Type: "select", Options: registerOptions(in.Register)}),
		b.add("field", components.Field{ID: "roles_claim_path", Label: msg.T("admin.providers.roles_claim_path.label"), Value: in.RolesClaimPath, Hint: msg.T("admin.providers.roles_claim_path.hint")}),
		b.add("choice", components.Choice{ID: "roles", Legend: msg.T("admin.providers.roles.label"), Options: roles, Multiple: true}),
		stacks,
		template.HTML(`<div id="discovery">`)+result+template.HTML(`</div>`), //nolint:gosec // literal wrappers around kit output
		template.HTML(`<div class="dialog-actions">`),                        //nolint:gosec // a literal wrapper
		b.add("button", components.Button{Text: msg.T("admin.providers.test.label"), Type: "submit", Attrs: map[string]string{
			"formaction": testPath, "hx-post": testPath, "hx-target": "#discovery", "hx-swap": "innerHTML", "hx-include": "closest form",
		}}),
		b.add("button", components.Button{Text: msg.T("admin.providers.save.label"), Type: "submit", Variant: "primary"}),
		template.HTML(`</div>`),
	)
	return b.add("card", components.Card{
		ID: "provider-form", Title: msg.T("admin.providers.details.label"),
		Body: form(action, csrf, fields),
	})
}

// tokenAuthOptions lists the token endpoint methods of ADR-035 decision 4.
func tokenAuthOptions(selected string) []components.Option {
	out := []components.Option{{Value: "", Text: msg.T("admin.providers.token_auth.preset.label"), Selected: selected == ""}}
	for _, m := range []oidcflow.TokenAuth{oidcflow.TokenAuthClientSecretBasic, oidcflow.TokenAuthClientSecretPost, oidcflow.TokenAuthPrivateKeyJWT, oidcflow.TokenAuthNone} {
		out = append(out, components.Option{Value: string(m), Text: string(m), Selected: string(m) == selected})
	}
	return out
}

// registerOptions lists the register actions of ADR-035 decision 3.
func registerOptions(selected string) []components.Option {
	return []components.Option{
		{Value: "", Text: msg.T("admin.providers.register.auto.label"), Selected: selected == ""},
		{Value: string(oidcflow.RegistrationPromptCreate), Text: msg.T("admin.providers.register.prompt.label"), Selected: selected == string(oidcflow.RegistrationPromptCreate)},
		{Value: string(oidcflow.RegistrationKeycloakEndpoint), Text: msg.T("admin.providers.register.keycloak.label"), Selected: selected == string(oidcflow.RegistrationKeycloakEndpoint)},
		{Value: string(oidcflow.RegistrationNone), Text: msg.T("admin.providers.register.none.label"), Selected: selected == string(oidcflow.RegistrationNone)},
	}
}

// createProvider saves a new record, pushes it to the live pairs, and
// shows the table with one line per target (ADR-035 decision 5).
func (p *Portal) createProvider(w http.ResponseWriter, r *http.Request, s session) error {
	in := readProviderInput(r)
	record, dynamic := in.record(nil)
	res, err := p.opts.Client.CreateAuthProvider(r.Context(), call(s, &adminv1.CreateAuthProviderRequest{
		Provider: record, DynamicRegistration: dynamic,
	}))
	if err != nil {
		return err
	}
	return p.providersPage(w, r, s, pushToasts("provider-added", res.Msg.GetPushes()))
}

// updateProvider saves the changes of one record and pushes them.
func (p *Portal) updateProvider(w http.ResponseWriter, r *http.Request, s session) error {
	got, err := p.opts.Client.GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	current := oidcflow.FromAdminProto(got.Msg.GetProvider())
	record, _ := readProviderInput(r).record(&current)
	res, err := p.opts.Client.UpdateAuthProvider(r.Context(), call(s, &adminv1.UpdateAuthProviderRequest{Provider: record}))
	if err != nil {
		return err
	}
	return p.providersPage(w, r, s, pushToasts("provider-saved", res.Msg.GetPushes()))
}

// toggleProvider turns one record on or off and pushes the state.
func (p *Portal) toggleProvider(w http.ResponseWriter, r *http.Request, s session) error {
	got, err := p.opts.Client.GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	record := got.Msg.GetProvider()
	record.Enabled = r.PostFormValue("enabled") == "true"
	if _, err := p.opts.Client.UpdateAuthProvider(r.Context(), call(s, &adminv1.UpdateAuthProviderRequest{Provider: record})); err != nil {
		return err
	}
	code := "provider-disabled"
	if record.GetEnabled() {
		code = "provider-enabled"
	}
	p.redirect(w, r, "/providers", code)
	return nil
}

// deleteProvider removes one provider.
func (p *Portal) deleteProvider(w http.ResponseWriter, r *http.Request, s session) error {
	_, err := p.opts.Client.DeleteAuthProvider(r.Context(), call(s, &adminv1.DeleteAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	p.redirect(w, r, "/providers", "provider-removed")
	return nil
}

// pushToasts turns the push report into toasts: the notice of the save,
// then one line per target, ok or warn.
func pushToasts(code string, pushes []*adminv1.PushResult) []components.Toast {
	out := notice(code)
	for _, push := range pushes {
		if push.GetOk() {
			out = append(out, components.Toast{Level: "ok", Text: msg.T("admin.providers.push.ok", push.GetPair())})
			continue
		}
		out = append(out, components.Toast{Level: "warn", Text: msg.T("admin.providers.push.failed", push.GetPair(), push.GetError())})
	}
	return out
}

// testDiscovery reads the metadata of the typed issuer through the
// guarded fetcher and shows what it found. An htmx request gets the
// result card alone; any other request gets the form page with the card
// and the typed values.
func (p *Portal) testDiscovery(w http.ResponseWriter, r *http.Request, s session) error {
	in := readProviderInput(r)
	b := p.blocks()
	card := p.discoveryCard(r.Context(), b, in)
	if b.err != nil {
		return b.err
	}
	if components.IsHTMX(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write([]byte(card))
		return err
	}
	return p.formPage(w, r, s, in, nil, card)
}

// discoveryCard runs the probe and draws its result, or its failure.
func (p *Portal) discoveryCard(ctx context.Context, b *blocks, in providerInput) template.HTML {
	res, err := onboard.Probe(ctx, p.opts.Fetcher, in.Issuer)
	if err != nil {
		return b.add("card", components.Card{
			ID: "discovery-result", Title: msg.T("admin.providers.discovery.label"),
			Body: b.add("badge", components.Badge{Status: "bad", Text: msg.T("admin.providers.discovery.failed", strings.TrimSuffix(err.Error(), "."))}),
		})
	}
	yes, no := msg.T("admin.providers.discovery.yes.label"), msg.T("admin.providers.discovery.no.label")
	registration := no
	if res.SupportsDynamicRegistration() {
		registration = yes + ": " + res.RegistrationEndpoint
	}
	register := msg.T("admin.providers.register.none.label")
	switch res.Registration(oidcflow.Kind(in.Kind)) {
	case oidcflow.RegistrationPromptCreate:
		register = msg.T("admin.providers.register.prompt.label")
	case oidcflow.RegistrationKeycloakEndpoint:
		register = msg.T("admin.providers.register.keycloak.label")
	}
	rows := []components.Row{
		{{Text: msg.T("admin.providers.discovery.issuer.label")}, {Text: res.Issuer}},
		{{Text: msg.T("admin.providers.discovery.document.label")}, {Text: res.DiscoveryURL}},
		{{Text: msg.T("admin.providers.discovery.authorize.label")}, {Text: res.AuthorizationEndpoint}},
		{{Text: msg.T("admin.providers.discovery.token.label")}, {Text: res.TokenEndpoint}},
		{{Text: msg.T("admin.providers.discovery.jwks.label")}, {Text: res.JWKSURI}},
		{{Text: msg.T("admin.providers.discovery.registration.label")}, {Text: registration}},
		{{Text: msg.T("admin.providers.discovery.register.label")}, {Text: register}},
		{{Text: msg.T("admin.providers.discovery.methods.label")}, {Text: strings.Join(res.EffectiveTokenAuthMethods(), ", ")}},
	}
	if len(res.ScopesSupported) > 0 {
		rows = append(rows, components.Row{{Text: msg.T("admin.providers.discovery.scopes.label")}, {Text: strings.Join(res.ScopesSupported, " ")}})
	}
	return b.add("card", components.Card{
		ID: "discovery-result", Title: msg.T("admin.providers.discovery.label"),
		Body: b.add("table", components.Table{
			Caption: msg.T("admin.providers.discovery.caption.label"),
			Columns: []string{msg.T("admin.providers.discovery.item.label"), msg.T("admin.providers.discovery.value.label")},
			Rows:    rows,
		}),
	})
}
