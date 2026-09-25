// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// errTarget reports a stack credential target that is not
// "<tenant id>|<stack>".
var errTarget = errors.New("portal: the target names no tenant on a stack")

// errDays reports an expiry that is not a positive number of days.
var errDays = errors.New("portal: the days value must be a positive number")

// keyExpiries are the expiry choices of the key form, in form order.
// The empty value makes a key with no end.
var keyExpiries = []struct {
	value string
	key   string
}{
	{"30", "admin.keys.expiry.30.label"},
	{"90", "admin.keys.expiry.90.label"},
	{"365", "admin.keys.expiry.365.label"},
	{"", "admin.keys.expiry.none.label"},
}

// defaultExpiry is the expiry the key form selects first.
const defaultExpiry = "90"

// registerKeys adds the API key pages (owner spec AD7, ADR-038).
func (p *Portal) registerKeys(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/keys", p.guarded(p.keys))
	mux.HandleFunc("POST "+at+"/keys", p.posted(p.createKey))
	mux.HandleFunc("POST "+at+"/keys/{id}/revoke", p.posted(p.revokeKey))
	mux.HandleFunc("POST "+at+"/keys/stack", p.posted(p.createStackCredential))
	mux.HandleFunc("POST "+at+"/keys/stack/delete", p.posted(p.deleteStackCredential))
}

// once is what the answer to a create form shows one time: the secret
// of a new API key, or a new stack credential with its secret.
type once struct {
	keySecret  string
	credential *adminv1.CreateStackCredentialResponse
}

// keys renders the key page.
func (p *Portal) keys(w http.ResponseWriter, r *http.Request, s session) error {
	return p.keysPage(w, r, s, once{}, nil)
}

// keysPage renders the VCA API keys and, where a live adapter lists
// tenant client credentials, the stack credentials. A new secret shows
// once, in a card at the top.
func (p *Portal) keysPage(w http.ResponseWriter, r *http.Request, s session, shown once, toasts []components.Toast) error {
	ctx := r.Context()
	filter := r.URL.Query().Get("tenant_id")
	res, err := p.opts.Client.ListApiKeys(ctx, call(s, &adminv1.ListApiKeysRequest{TenantId: filter, Page: &commonv1.Pagination{PageSize: 500}}))
	if err != nil {
		return err
	}
	tenants, err := p.opts.Client.ListTenants(ctx, call(s, &adminv1.ListTenantsRequest{Page: &commonv1.Pagination{PageSize: 500}}))
	if err != nil {
		return err
	}
	f := p.frame(ctx)
	b := p.blocks()
	secret := p.secretCards(b, shown)
	vca := p.vcaKeys(b, s, res.Msg.GetKeys(), tenants.Msg.GetTenants())
	var stack template.HTML
	lead := msg.T("admin.keys.lead")
	if f.has(backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS) {
		lead = msg.T("admin.keys.stack.lead")
		if stack, err = p.stackCredentials(ctx, b, s, f, tenants.Msg.GetTenants()); err != nil {
			return err
		}
	}
	if b.err != nil {
		return b.err
	}
	if toasts == nil {
		toasts = notice(r.URL.Query().Get("notice"))
	}
	actions := b.add("button", components.Button{Text: msg.T("admin.keys.new.label"), Href: "#create-key", Variant: "primary"})
	if len(tenants.Msg.GetTenants()) == 0 {
		actions = ""
	}
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       msg.T("admin.nav.api_keys.label"),
		Lead:        lead,
		Actions:     actions,
		Description: lead,
		Content:     components.Join(secret, vca, stack),
		Toasts:      toasts,
	})
}

// secretCards shows a new secret once: of an API key, or of a stack
// credential with its client id.
func (p *Portal) secretCards(b *blocks, shown once) template.HTML {
	if shown.keySecret != "" {
		return b.add("card", components.Card{
			ID: "new-secret", Title: msg.T("admin.keys.secret.label"), Text: msg.T("admin.keys.secret.text"),
			Body:   b.add("code", components.Code{ID: "new-secret-value", Label: msg.T("admin.keys.secret.value.label"), Text: shown.keySecret}),
			Footer: msg.T("admin.keys.secret.footer"),
		})
	}
	if c := shown.credential; c != nil {
		return b.add("card", components.Card{
			ID: "new-credential", Title: msg.T("admin.keys.stack.secret.label"),
			Text: msg.T("admin.keys.stack.secret.text", c.GetCredential().GetStackName()),
			Body: components.Join(
				b.add("code", components.Code{ID: "new-client-id", Label: msg.T("admin.keys.stack.client_id.label"), Text: c.GetCredential().GetCredential().GetClientId()}),
				b.add("code", components.Code{ID: "new-client-secret", Label: msg.T("admin.keys.stack.client_secret.label"), Text: c.GetClientSecret()}),
			),
			Footer: msg.T("admin.keys.secret.footer"),
		})
	}
	return ""
}

// vcaKeys is the section of the VCA API keys: the table and the
// create form. The query value tenant_id filters the table. Without a
// tenant the form waits for one.
func (p *Portal) vcaKeys(b *blocks, s session, keys []*adminv1.ApiKey, tenants []*adminv1.Tenant) template.HTML {
	at := p.opts.Prefix
	names := make(map[string]string, len(tenants))
	for _, t := range tenants {
		names[t.GetId()] = t.GetDisplayName()
	}
	now := time.Now()
	rows := make([]components.Row, 0, len(keys))
	for _, k := range keys {
		tenant := names[k.GetTenantId()]
		if tenant == "" {
			tenant = k.GetTenantId()
		}
		expires := msg.T("admin.keys.expiry.never.label")
		if k.GetExpiresAt() != nil {
			expires = k.GetExpiresAt().AsTime().UTC().Format(DateFormat)
		}
		rows = append(rows, components.Row{
			{Text: k.GetDisplayName()},
			{HTML: code(k.GetPrefix() + "...")},
			{Text: tenant},
			{Text: roleText(k.GetRoles())},
			{Text: expires},
			{HTML: keyState(b, k, now)},
			{HTML: form(at+"/keys/"+k.GetId()+"/revoke", s.CSRF,
				b.add("button", components.Button{Text: msg.T("admin.keys.revoke.label"), Type: "submit", Variant: "danger"}))},
		})
	}
	options := make([]components.Option, 0, len(tenants))
	for _, t := range tenants {
		options = append(options, components.Option{Value: t.GetId(), Text: t.GetDisplayName()})
	}
	table := b.add("table", components.Table{
		ID: "keys", Caption: msg.T("admin.keys.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.keys.column.name.label"), msg.T("admin.keys.column.prefix.label"), msg.T("admin.keys.column.tenant.label"),
			msg.T("admin.keys.column.roles.label"), msg.T("admin.keys.column.expires.label"), msg.T("admin.keys.column.state.label"),
			msg.T("admin.keys.column.actions.label"),
		},
		Rows: rows, Empty: msg.T("admin.keys.empty"),
	})
	var create template.HTML
	if len(tenants) == 0 {
		create = b.add("empty", components.Empty{
			Title: msg.T("admin.keys.no_tenant.title"), Text: msg.T("admin.keys.no_tenant.text"),
			Action: components.Button{Text: msg.T("admin.tenants.new.label"), Href: at + "/tenants#create-tenant", Variant: "primary"},
		})
	} else {
		expiries := make([]components.Option, 0, len(keyExpiries))
		for _, e := range keyExpiries {
			expiries = append(expiries, components.Option{Value: e.value, Text: msg.T(e.key), Selected: e.value == defaultExpiry})
		}
		create = b.add("card", components.Card{
			ID: "create-key", Title: msg.T("admin.keys.new.label"), Text: msg.T("admin.keys.new.text"),
			Body: form(at+"/keys", s.CSRF,
				b.add("field", components.Field{ID: "display_name", Label: msg.T("admin.keys.display_name.label"), Required: true}),
				b.add("field", components.Field{ID: "tenant_id", Label: msg.T("admin.keys.column.tenant.label"), Type: "select", Options: options,
					Hint: msg.T("admin.keys.tenant.hint")}),
				b.add("field", components.Field{ID: "role", Label: msg.T("admin.keys.role.label"), Type: "select", Options: []components.Option{
					{Value: "admin", Text: msg.T("role.admin.label"), Selected: true},
					{Value: "issuer", Text: msg.T("role.issuer.label")},
					{Value: "verifier", Text: msg.T("role.verifier.label")},
					{Value: "holder", Text: msg.T("role.holder.label")},
				}}),
				b.add("field", components.Field{ID: "expires_days", Label: msg.T("admin.keys.expiry.label"), Type: "select", Options: expiries,
					Hint: msg.T("admin.keys.expiry.hint")}),
				b.add("button", components.Button{Text: msg.T("admin.keys.create.label"), Type: "submit", Variant: "primary"}),
			),
		})
	}
	return b.add("block", components.Block{
		ID: "vca-keys", Title: msg.T("admin.keys.vca.label"), Lead: msg.T("admin.keys.vca.lead"),
		Body: components.Join(table, create),
	})
}

// keyState is the badge of a key: revoked, expired, or active.
func keyState(b *blocks, k *adminv1.ApiKey, now time.Time) template.HTML {
	switch {
	case k.GetRevokedAt() != nil:
		return b.add("badge", components.Badge{Status: "bad", Text: msg.T("admin.keys.state.revoked.label")})
	case k.GetExpiresAt() != nil && !now.Before(k.GetExpiresAt().AsTime()):
		return b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.keys.state.expired.label")})
	}
	return b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.keys.state.active.label")})
}

// stackCredentials is the section of the client credentials of the
// stack tenants (ADR-038 decision 2). The caller shows it only when a
// live adapter lists tenant client credentials.
func (p *Portal) stackCredentials(ctx context.Context, b *blocks, s session, f frame, tenants []*adminv1.Tenant) (template.HTML, error) {
	at := p.opts.Prefix
	offered := map[string]stacks.Stack{}
	for _, st := range stacks.With(f.snap, backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS) {
		offered[st.Dpg.String()] = st
	}
	names := make(map[string]string, len(tenants))
	var targets []components.Option
	for _, t := range tenants {
		names[t.GetId()] = t.GetDisplayName()
		for _, bd := range t.GetBindings() {
			if st, ok := offered[bd.GetStack().String()]; ok {
				targets = append(targets, components.Option{
					Value: t.GetId() + "|" + bd.GetStack().String(),
					Text:  msg.T("admin.keys.stack.target.value.label", t.GetDisplayName(), st.Name),
				})
			}
		}
	}
	block := components.Block{ID: "stack-credentials", Title: msg.T("admin.keys.stack.label"), Lead: msg.T("admin.keys.stack.block.lead")}
	if len(targets) == 0 {
		block.Body = b.add("empty", components.Empty{
			Title: msg.T("admin.keys.stack.empty.title"), Text: msg.T("admin.keys.stack.empty.text"),
			Action: components.Button{Text: msg.T("admin.keys.stack.tenants.label"), Href: at + "/tenants"},
		})
		return b.add("block", block), nil
	}
	res, err := p.opts.Client.ListStackCredentials(ctx, call(s, &adminv1.ListStackCredentialsRequest{}))
	if err != nil {
		return "", err
	}
	rows := make([]components.Row, 0, len(res.Msg.GetCredentials()))
	for _, c := range res.Msg.GetCredentials() {
		created := ""
		if c.GetCredential().GetCreatedAt() != nil {
			created = c.GetCredential().GetCreatedAt().AsTime().UTC().Format(DateFormat)
		}
		rows = append(rows, components.Row{
			{Text: c.GetCredential().GetName()},
			{HTML: code(c.GetCredential().GetClientId())},
			{Text: names[c.GetTenantId()]},
			{Text: c.GetStackName()},
			{Text: created},
			{HTML: form(at+"/keys/stack/delete", s.CSRF,
				template.HTML(`<input type="hidden" name="tenant_id" value="`+template.HTMLEscapeString(c.GetTenantId())+`">`+ //nolint:gosec // every value is escaped
					`<input type="hidden" name="stack" value="`+template.HTMLEscapeString(c.GetStack().String())+`">`+
					`<input type="hidden" name="id" value="`+template.HTMLEscapeString(c.GetCredential().GetId())+`">`),
				b.add("button", components.Button{Text: msg.T("common.delete.label"), Type: "submit", Variant: "danger"}))},
		})
	}
	var faults template.HTML
	for _, e := range res.Msg.GetErrors() {
		faults += hint(msg.T("admin.keys.stack.fault", e))
	}
	table := b.add("table", components.Table{
		ID: "stack-credential-list", Caption: msg.T("admin.keys.stack.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.keys.column.name.label"), msg.T("admin.keys.stack.column.client_id.label"),
			msg.T("admin.keys.column.tenant.label"), msg.T("admin.keys.stack.column.stack.label"),
			msg.T("admin.keys.stack.column.created.label"), msg.T("admin.keys.column.actions.label"),
		},
		Rows: rows, Empty: msg.T("admin.keys.stack.none"),
	})
	create := b.add("card", components.Card{
		ID: "create-stack-credential", Title: msg.T("admin.keys.stack.new.label"), Text: msg.T("admin.keys.stack.new.text"),
		Body: form(at+"/keys/stack", s.CSRF,
			b.add("field", components.Field{ID: "target", Label: msg.T("admin.keys.stack.target.label"), Type: "select", Options: targets}),
			b.add("field", components.Field{ID: "credential_name", Name: "display_name", Label: msg.T("admin.keys.display_name.label"), Required: true}),
			b.add("button", components.Button{Text: msg.T("admin.keys.stack.create.label"), Type: "submit", Variant: "primary"}),
		),
	})
	block.Body = components.Join(faults, table, create)
	return b.add("block", block), nil
}

// createKey creates one key and shows its secret once.
func (p *Portal) createKey(w http.ResponseWriter, r *http.Request, s session) error {
	req := &adminv1.CreateApiKeyRequest{
		DisplayName: r.PostFormValue("display_name"),
		TenantId:    r.PostFormValue("tenant_id"),
		Roles:       []commonv1.Role{service.RoleValue(r.PostFormValue("role"))},
	}
	if days := strings.TrimSpace(r.PostFormValue("expires_days")); days != "" {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return connect.NewError(connect.CodeInvalidArgument, errDays)
		}
		req.ExpiresAt = timestamp(time.Now().AddDate(0, 0, n))
	}
	res, err := p.opts.Client.CreateApiKey(r.Context(), call(s, req))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	return p.keysPage(w, r, s, once{keySecret: res.Msg.GetSecret()}, []components.Toast{{Level: "ok", Text: msg.T("admin.keys.created")}})
}

// revokeKey revokes one key.
func (p *Portal) revokeKey(w http.ResponseWriter, r *http.Request, s session) error {
	_, err := p.opts.Client.RevokeApiKey(r.Context(), call(s, &adminv1.RevokeApiKeyRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	p.redirect(w, r, "/keys", "key-revoked")
	return nil
}

// createStackCredential creates one client credential on a stack tenant
// and shows its secret once, in the answer. A reload does not show it.
func (p *Portal) createStackCredential(w http.ResponseWriter, r *http.Request, s session) error {
	tenantID, stack, ok := strings.Cut(r.PostFormValue("target"), "|")
	if !ok || tenantID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errTarget)
	}
	d, err := stackValue(stack)
	if err != nil {
		return err
	}
	res, err := p.opts.Client.CreateStackCredential(r.Context(), call(s, &adminv1.CreateStackCredentialRequest{
		TenantId: tenantID, Stack: d, DisplayName: r.PostFormValue("display_name"),
	}))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	return p.keysPage(w, r, s, once{credential: res.Msg}, []components.Toast{{Level: "ok", Text: msg.T("admin.keys.stack.created")}})
}

// deleteStackCredential removes one client credential of a stack tenant.
func (p *Portal) deleteStackCredential(w http.ResponseWriter, r *http.Request, s session) error {
	d, err := stackValue(r.PostFormValue("stack"))
	if err != nil {
		return err
	}
	if _, err := p.opts.Client.DeleteStackCredential(r.Context(), call(s, &adminv1.DeleteStackCredentialRequest{
		TenantId: r.PostFormValue("tenant_id"), Stack: d, Id: r.PostFormValue("id"),
	})); err != nil {
		return err
	}
	p.redirect(w, r, "/keys", "stack-credential-deleted")
	return nil
}
