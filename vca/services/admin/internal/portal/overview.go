// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// checklistRoles are the roles the first run checklist wants a login
// provider for, in the order the detail names a gap.
var checklistRoles = []string{"admin", "issuer", "holder", "verifier"}

// counts is what the overview cards and the checklist read, through
// the RPCs of the service.
type counts struct {
	trust       int
	external    int
	hasRegistry bool
	providers   []oidcflow.Provider
	tenants     int
	keys        int
	events      int
}

// overview draws board Admin-Portal: the stat cards, the first run
// checklist, and the service health (ADR-035 decision 6).
func (p *Portal) overview(w http.ResponseWriter, r *http.Request, s session) error {
	ctx := r.Context()
	c, err := p.counts(ctx, s)
	if err != nil {
		return err
	}
	healthRes, err := p.opts.Client.GetServiceHealth(ctx, call(s, &adminv1.GetServiceHealthRequest{}))
	if err != nil {
		return err
	}
	f := p.frame(ctx)
	b := p.blocks()
	at := p.opts.Prefix
	var actions template.HTML
	if console := adminConsole(c.providers); console != "" {
		actions = b.add("button", components.Button{Text: msg.T("admin.nav.console.label"), Href: console})
	}
	stats := components.Join(
		b.add("stat", components.Stat{Label: msg.T("admin.stat.trust_list.label"), Value: c.trustValue(),
			Text: msg.T("admin.stat.trust_list.text"), Href: at + "/trust"}),
		b.add("stat", components.Stat{Label: msg.T("admin.nav.trust_registries.label"), Value: c.registriesValue(),
			Text: msg.T("admin.stat.registries.text"), Href: at + "/trust/registries"}),
		b.add("stat", components.Stat{Label: msg.T("admin.nav.providers.label"), Value: plural(len(c.providers), "admin.stat.providers"),
			Text: plural(c.realms(), "admin.stat.providers.realm") + ". " + msg.T("admin.stat.providers.text"), Href: at + "/providers"}),
		b.add("stat", components.Stat{Label: msg.T("admin.nav.tenants.label"), Value: plural(c.tenants, "admin.stat.tenants"),
			Text: msg.T("admin.stat.tenants.text"), Href: at + "/tenants"}),
		b.add("stat", components.Stat{Label: msg.T("admin.nav.api_keys.label"), Value: c.keysValue(),
			Text: msg.T("admin.stat.api_keys.text"), Href: at + "/keys"}),
		b.add("stat", components.Stat{Label: msg.T("admin.nav.audit.label"), Value: plural(c.events, "admin.stat.audit"),
			Text: msg.T("admin.stat.audit.text"), Href: at + "/audit"}),
	)
	checklist := b.add("checklist", components.Checklist{
		ID: "first-run", Title: msg.T("admin.checklist.title.label"), Note: msg.T("admin.checklist.note"),
		Items: p.checklist(ctx, c),
	})
	health := p.healthTable(b, healthRes.Msg)
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       msg.T("common.overview.label"),
		Lead:        msg.T("admin.overview.lead"),
		Actions:     actions,
		Description: msg.T("admin.overview.lead"),
		Content: components.Join(template.HTML(`<div class="stats">`)+stats+template.HTML(`</div>`), //nolint:gosec // literal wrappers around kit output
			checklist, health),
		Toasts: notice(r.URL.Query().Get("notice")),
	})
}

// counts reads every number of the overview through the RPCs.
func (p *Portal) counts(ctx context.Context, s session) (counts, error) {
	var c counts
	// The card counts the issuers a verifier accepts: active issuers.
	trust, err := p.opts.Client.ListTrustEntries(ctx, call(s, &adminv1.ListTrustEntriesRequest{
		Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_ACTIVE,
	}))
	switch {
	case err != nil && connect.CodeOf(err) == connect.CodeFailedPrecondition:
	case err != nil:
		return c, err
	default:
		c.hasRegistry = true
		c.trust = int(trust.Msg.GetPage().GetTotalSize())
		regs, rerr := p.opts.Client.ListTrustRegistries(ctx, call(s, &adminv1.ListTrustRegistriesRequest{}))
		if rerr != nil {
			return c, rerr
		}
		c.external = len(regs.Msg.GetRegistries())
	}
	providers, err := p.opts.Client.ListAuthProviders(ctx, call(s, &adminv1.ListAuthProvidersRequest{
		Page: &commonv1.Pagination{PageSize: 500},
	}))
	if err != nil {
		return c, err
	}
	for _, m := range providers.Msg.GetProviders() {
		c.providers = append(c.providers, oidcflow.FromAdminProto(m))
	}
	tenants, err := p.opts.Client.ListTenants(ctx, call(s, &adminv1.ListTenantsRequest{}))
	if err != nil {
		return c, err
	}
	c.tenants = int(tenants.Msg.GetPage().GetTotalSize())
	keys, err := p.opts.Client.ListApiKeys(ctx, call(s, &adminv1.ListApiKeysRequest{
		Page: &commonv1.Pagination{PageSize: 500},
	}))
	if err != nil {
		return c, err
	}
	for _, k := range keys.Msg.GetKeys() {
		if k.GetRevokedAt() == nil {
			c.keys++
		}
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	events, err := p.opts.Client.QueryAuditLog(ctx, call(s, &adminv1.QueryAuditLogRequest{
		From: timestamp(today), Page: &commonv1.Pagination{PageSize: 1},
	}))
	if err != nil {
		return c, err
	}
	c.events = int(events.Msg.GetPage().GetTotalSize())
	return c, nil
}

// registriesValue is the value of the registries card.
func (c counts) registriesValue() string {
	if c.external == 0 {
		return msg.T("admin.stat.registries.value.label")
	}
	return msg.T("admin.stat.registries.external.label", strconv.Itoa(c.external))
}

// trustValue is the value of the trust list card.
func (c counts) trustValue() string {
	if !c.hasRegistry {
		return msg.T("admin.stat.trust_list.none_registry.label")
	}
	return plural(c.trust, "admin.stat.trust_list")
}

// keysValue is the value of the API keys card.
func (c counts) keysValue() string {
	if c.keys == 0 {
		return msg.T("admin.stat.api_keys.none.label")
	}
	return plural(c.keys, "admin.stat.api_keys")
}

// realms counts the distinct realm labels of the enabled providers.
func (c counts) realms() int {
	seen := map[string]bool{}
	for _, pr := range c.providers {
		if pr.Enabled && pr.Realm != "" {
			seen[pr.Realm] = true
		}
	}
	return len(seen)
}

// plural returns the catalogue phrase of a count: the ".one.label" key
// for one, else the ".value.label" key with the number.
func plural(n int, key string) string {
	if n == 1 {
		return msg.T(key + ".one.label")
	}
	return msg.T(key+".value.label", strconv.Itoa(n))
}

// checklist is the first run checklist of ADR-035 decision 6. The
// reader is a bound admin, so the first item is done. Self registration
// counts as off when no enabled admin provider offers a register action
// on the sign in page. The trust list wants one entry. Every role wants
// one enabled provider.
func (p *Portal) checklist(ctx context.Context, c counts) []components.Check {
	adminRealm := ""
	registers, admins := false, 0
	roles := map[string]bool{}
	for _, pr := range c.providers {
		if !pr.Enabled {
			continue
		}
		for _, r := range pr.Roles {
			roles[r] = true
		}
		if !hasRole(pr, role) {
			continue
		}
		admins++
		if adminRealm == "" {
			adminRealm = pr.Realm
			if adminRealm == "" {
				adminRealm = pr.DisplayName
			}
		}
		if p.registers(ctx, pr) {
			registers = true
		}
	}
	var missing []string
	for _, r := range checklistRoles {
		if !roles[r] {
			missing = append(missing, msg.T("role."+r+".plural.label"))
		}
	}
	providersDetail := msg.T("admin.checklist.providers.detail")
	if len(missing) > 0 {
		providersDetail = msg.T("admin.checklist.providers.missing", strings.Join(missing, ", "))
	}
	return []components.Check{
		{Text: msg.T("admin.checklist.register.text"), Detail: msg.T("admin.checklist.register.detail", adminRealm), Done: true},
		{Text: msg.T("admin.checklist.self_reg.text"), Detail: msg.T("admin.checklist.self_reg.detail"), Done: admins > 0 && !registers},
		{Text: msg.T("admin.checklist.trust.text"), Detail: msg.T("admin.checklist.trust.detail"), Done: c.trust > 0},
		{Text: msg.T("admin.checklist.providers.text"), Detail: providersDetail, Done: len(missing) == 0},
	}
}

// registers reports whether the sign in page offers a register action
// for a provider, with the same rule as the chooser (ADR-035 decision 3).
func (p *Portal) registers(ctx context.Context, pr oidcflow.Provider) bool {
	var m oidcflow.Metadata
	if flow := p.opts.Login.Flow(); flow != nil {
		m = anyval.OrZero(flow.Metadata(ctx, pr))
	}
	return pr.EffectiveRegistration(m) != oidcflow.RegistrationNone
}

// hasRole reports whether a provider lists a role.
func hasRole(pr oidcflow.Provider, want string) bool {
	for _, r := range pr.Roles {
		if r == want {
			return true
		}
	}
	return false
}

// healthTable draws the service health of the deployment.
func (p *Portal) healthTable(b *blocks, res *adminv1.GetServiceHealthResponse) template.HTML {
	rows := make([]components.Row, 0, len(res.GetServices()))
	for _, svc := range res.GetServices() {
		status, text := "bad", "Not ready"
		if svc.GetReady() {
			status, text = "ok", "Ready"
		}
		rows = append(rows, components.Row{
			{Text: svc.GetName()},
			{HTML: b.add("badge", components.Badge{Status: status, Text: text})},
			{Text: svc.GetVersion()},
			{Text: checkedText(svc)},
		})
	}
	caption := fmt.Sprintf("Service health, %d services", len(rows))
	if len(rows) == 1 {
		caption = "Service health, 1 service"
	}
	return b.add("table", components.Table{
		ID: "health", Caption: caption,
		Columns: []string{"Service", "State", "Version", "Last probe"}, Rows: rows,
		Empty: "No service is configured. Set VCA_ADMIN_SERVICES to name each service.",
	})
}
