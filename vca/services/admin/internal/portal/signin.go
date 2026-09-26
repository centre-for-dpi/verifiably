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
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The holder authorization server of an issuer stack keeps a provider
// registry of its own. It binds an offer or finds a holder only on a
// claim the provider vouches for (ADR-056 decision 2). The admin edits
// the claims each provider verifies here, through the provider RPCs of
// the adapter on the compose network, with the admin session.

// maxVerifiedClaims caps the claims one provider lists.
const maxVerifiedClaims = 16

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

// signInClient returns the provider RPC client of an adapter.
func (p *Portal) signInClient(adapter string) adminv1connect.AdminServiceClient {
	client := p.opts.PeerClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return adminv1connect.NewAdminServiceClient(client, adapter)
}

// signInBlock draws the card of every holder authorization server: its
// providers with the claims they verify, and a form per provider.
func (p *Portal) signInBlock(ctx context.Context, b *blocks, f frame, s session) template.HTML {
	targets := signInTargets(f)
	if len(targets) == 0 {
		return ""
	}
	parts := make([]template.HTML, 0, len(targets))
	for _, target := range targets {
		res, err := p.signInClient(target.adapter).ListAuthProviders(ctx, call(s, &adminv1.ListAuthProvidersRequest{}))
		if err != nil {
			parts = append(parts, b.add("note", components.Note{Label: target.name, Text: msg.T("admin.signin.down")}))
			continue
		}
		rows := make([]components.Row, 0, len(res.Msg.GetProviders()))
		for i, m := range res.Msg.GetProviders() {
			pr := oidcflow.FromAdminProto(m)
			field := b.add("field", components.Field{
				ID: "verified-claims-" + target.pair + "-" + strconv.Itoa(i), Name: "verified_claims",
				Label: msg.T("admin.signin.claims.label", pr.DisplayName), Value: strings.Join(pr.VerifiedClaims, ", "),
				Hint: msg.T("admin.signin.claims.hint"), Attrs: map[string]string{"maxlength": "500", "autocomplete": "off"},
			})
			save := b.add("button", components.Button{Text: msg.T("admin.signin.save.label"), Type: "submit"})
			rows = append(rows, components.Row{
				{Text: pr.DisplayName}, {Text: issuerOf(pr.DiscoveryURL)},
				{HTML: form(p.opts.Prefix+"/providers/signin/"+target.pair+"/"+pr.ID, s.CSRF, field, save)},
			})
		}
		parts = append(parts, b.add("table", components.Table{
			ID: "signin-" + target.pair, Caption: msg.T("admin.signin.caption.label", target.name),
			Columns: []string{msg.T("admin.providers.column.provider.label"), msg.T("admin.signin.column.issuer.label"), msg.T("admin.signin.column.claims.label")},
			Rows:    rows, Empty: msg.T("admin.signin.empty"),
		}))
	}
	return b.add("card", components.Card{
		ID: "holder-sign-in", Title: msg.T("admin.signin.title.label"), Text: msg.T("admin.signin.lead"), Body: components.Join(parts...),
	})
}

// saveSignInClaims stores the claims one provider of a holder
// authorization server verifies.
func (p *Portal) saveSignInClaims(w http.ResponseWriter, r *http.Request, s session) error {
	var target *signInTarget
	for _, t := range signInTargets(p.frame(r.Context())) {
		if t.pair == r.PathValue("pair") {
			target = &t
		}
	}
	if target == nil {
		return connect.NewError(connect.CodeNotFound, errors.New("portal: the pair runs no holder authorization server"))
	}
	claims, err := parseClaims(r.PostFormValue("verified_claims"))
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	client := p.signInClient(target.adapter)
	got, err := client.GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	record := got.Msg.GetProvider()
	record.VerifiedClaims = claims
	if _, err := client.UpdateAuthProvider(r.Context(), call(s, &adminv1.UpdateAuthProviderRequest{Provider: record})); err != nil {
		return err
	}
	return p.providersPage(w, r, s, notice("signin-claims-saved"))
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
