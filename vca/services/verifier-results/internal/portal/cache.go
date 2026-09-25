// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Cache is the trust cache of the policy service of the pair
// (ADR-041 decision 5). The pages call it on the compose network.
type Cache interface {
	GetCacheState(context.Context, *connect.Request[policyv1.GetCacheStateRequest]) (*connect.Response[policyv1.GetCacheStateResponse], error)
	SyncCache(context.Context, *connect.Request[policyv1.SyncCacheRequest]) (*connect.Response[policyv1.SyncCacheResponse], error)
	SetCachePolicy(context.Context, *connect.Request[policyv1.SetCachePolicyRequest]) (*connect.Response[policyv1.SetCachePolicyResponse], error)
}

// errNoCache reports a portal without a policy service.
var errNoCache = errors.New("portal: no policy service")

// The choices of the policy form. The value is a Go duration.
var (
	trustChoices  = []time.Duration{time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}
	keysChoices   = []time.Duration{6 * time.Hour, 12 * time.Hour, 24 * time.Hour, 48 * time.Hour, 168 * time.Hour}
	statusChoices = []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour}
	windowChoices = []time.Duration{time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour, 48 * time.Hour, 72 * time.Hour, 168 * time.Hour}
)

// The boxes of the offline choice.
const (
	boxAllowOffline = "allow_offline"
	boxMarkStale    = "mark_stale"
	boxRefuseStale  = "refuse_stale_status"
)

// cacheState reads the state of the trust cache.
func (p *Portal) cacheState(ctx context.Context) (*policyv1.GetCacheStateResponse, error) {
	if p.opts.Cache == nil {
		return nil, errNoCache
	}
	res, err := p.opts.Cache.GetCacheState(ctx, connect.NewRequest(&policyv1.GetCacheStateRequest{}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// cache draws board Verifier-Caching: the age and the counts of each
// kind, Sync now, every source, and the policy form.
func (p *Portal) cache(w http.ResponseWriter, r *http.Request) error {
	var toasts []components.Toast
	switch q := r.URL.Query(); {
	case q.Get("synced") != "":
		toasts = append(toasts, components.Toast{Level: "ok", Text: syncedText(q.Get("failed"))})
	case q.Get("saved") != "":
		toasts = append(toasts, components.Toast{Level: "ok", Text: msg.T("verifier.cache.saved")})
	}
	return p.renderCache(w, r, http.StatusOK, toasts, nil)
}

// syncedText says what Sync now did.
func syncedText(failed string) string {
	if n, err := strconv.Atoi(failed); err == nil && n > 0 {
		return msg.T("verifier.cache.synced.failed", failed, plural(n, "source", "sources"))
	}
	return msg.T("verifier.cache.synced")
}

// plural returns one or many by n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// renderCache writes the cache page with a status, toasts, and the
// problems of a posted policy form by field.
func (p *Portal) renderCache(w http.ResponseWriter, r *http.Request, status int, toasts []components.Toast, problems map[string]string) error {
	b := &blocks{kit: p.opts.Cards.Kit()}
	page := components.Page{
		Title: msg.T("verifier.nav.cache.label"), Lead: msg.T("verifier.cache.lead"), Description: msg.T("verifier.cache.lead"),
		Toasts: toasts,
	}
	state, err := p.cacheState(r.Context())
	if err != nil {
		page.Content = b.add("empty", components.Empty{
			Title: msg.T("verifier.cache.down.title"), Text: msg.T("verifier.cache.down.text"),
			Action: components.Button{Text: msg.T("verifier.cache.retry.label"), Href: p.opts.Prefix + "/cache/"},
		})
	} else {
		page.Actions = p.syncForm(r, b)
		page.Content = components.Join(
			template.HTML(`<div class="stats">`), p.kindStats(b, state), template.HTML(`</div>`),
			p.policyForm(r, b, state.GetPolicy(), problems),
			p.sourceTable(b, state),
		)
	}
	if b.err != nil {
		return b.err
	}
	return p.render(withStatus(w, status), r, "cache", page)
}

// syncForm is the Sync now button in a form that posts.
func (p *Portal) syncForm(r *http.Request, b *blocks) template.HTML {
	button := b.add("button", components.Button{Text: msg.T("verifier.cache.sync.label"), Type: "submit", Variant: "primary"})
	return template.HTML(`<form method="post" action="`+template.HTMLEscapeString(p.opts.Prefix+"/cache/sync")+`">`) + //nolint:gosec // the path is escaped
		staffsession.HiddenField(r.Context()) + button + template.HTML(`</form>`)
}

// kindStats is one stat card per kind: the age of its oldest copy and
// its counts.
func (p *Portal) kindStats(b *blocks, state *policyv1.GetCacheStateResponse) template.HTML {
	byKind := map[policyv1.CacheKind]*policyv1.CacheKindState{}
	for _, k := range state.GetKinds() {
		byKind[k.GetKind()] = k
	}
	var parts []template.HTML
	for _, kind := range []policyv1.CacheKind{
		policyv1.CacheKind_CACHE_KIND_TRUST_LIST, policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS, policyv1.CacheKind_CACHE_KIND_STATUS_LIST,
	} {
		k := byKind[kind]
		if k == nil {
			k = &policyv1.CacheKindState{Kind: kind}
		}
		text := kindText(k)
		if n := int(k.GetFailed()); n > 0 {
			text += " " + msg.T("verifier.cache.failed.text", strconv.Itoa(n), plural(n, "source", "sources"))
		}
		parts = append(parts, b.add("stat", components.Stat{
			Label: kindLabel(kind), Value: p.syncedValue(k), Text: text,
			Href: "#cache-sources", LinkText: msg.T("verifier.cache.sources.link.label"),
		}))
	}
	return components.Join(parts...)
}

// syncedValue says how long ago the oldest copy of a kind arrived.
func (p *Portal) syncedValue(k *policyv1.CacheKindState) string {
	if k.GetSyncedAt() == nil {
		return msg.T("verifier.cache.never.label")
	}
	return msg.T("verifier.cache.synced.label", cards.Age(p.opts.Now().Sub(k.GetSyncedAt().AsTime())))
}

// kindLabel names a kind.
func kindLabel(k policyv1.CacheKind) string {
	switch k {
	case policyv1.CacheKind_CACHE_KIND_TRUST_LIST:
		return msg.T("verifier.cache.trust.label")
	case policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS:
		return msg.T("verifier.cache.keys.label")
	case policyv1.CacheKind_CACHE_KIND_STATUS_LIST:
		return msg.T("verifier.cache.status.label")
	case policyv1.CacheKind_CACHE_KIND_UNSPECIFIED:
	}
	return msg.T("common.unknown.label")
}

// kindText counts what the copies of a kind hold.
func kindText(k *policyv1.CacheKindState) string {
	items, sources, issuers := strconv.Itoa(int(k.GetItems())), strconv.Itoa(int(k.GetSources())), strconv.Itoa(int(k.GetIssuers()))
	switch k.GetKind() {
	case policyv1.CacheKind_CACHE_KIND_TRUST_LIST:
		return msg.T("verifier.cache.trust.text", items, issuers)
	case policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS:
		return msg.T("verifier.cache.keys.text", items, sources)
	case policyv1.CacheKind_CACHE_KIND_STATUS_LIST, policyv1.CacheKind_CACHE_KIND_UNSPECIFIED:
	}
	return msg.T("verifier.cache.status.text", sources, issuers)
}

// sourceTable lists the sources of each kind with their last read,
// one table per kind, so the columns fit the page.
func (p *Portal) sourceTable(b *blocks, state *policyv1.GetCacheStateResponse) template.HTML {
	var tables []template.HTML
	for _, kind := range []struct {
		kind policyv1.CacheKind
		id   string
	}{
		{policyv1.CacheKind_CACHE_KIND_TRUST_LIST, "trust"}, {policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS, "keys"},
		{policyv1.CacheKind_CACHE_KIND_STATUS_LIST, "status"},
	} {
		table := components.Table{
			ID: "cache-" + kind.id + "-rows", Caption: kindLabel(kind.kind),
			Columns: []string{
				msg.T("verifier.cache.column.source.label"), msg.T("verifier.cache.column.registry.label"),
				msg.T("verifier.cache.column.synced.label"), msg.T("verifier.cache.column.signed.label"),
				msg.T("verifier.cache.column.state.label"),
			},
			Empty: msg.T("verifier.cache.sources.none"),
		}
		for _, s := range state.GetSources() {
			if s.GetKind() != kind.kind {
				continue
			}
			synced := msg.T("verifier.cache.never.label")
			if s.GetSyncedAt() != nil {
				synced = msg.T("verifier.cache.ago.label", cards.Age(p.opts.Now().Sub(s.GetSyncedAt().AsTime())))
			}
			registry := s.GetRegistryName()
			if registry == "" {
				registry = msg.T("verifier.cache.local.label")
			}
			st := b.add("badge", components.Badge{Status: "ok", Text: msg.T("verifier.cache.good.label")})
			if e := s.GetLastError(); e != "" {
				st = b.add("badge", components.Badge{Status: "bad", Text: msg.T("verifier.cache.failed.label")}) +
					template.HTML(" ") + template.HTML(template.HTMLEscapeString(reason(e, s.GetSource()))) //nolint:gosec // the text is escaped
			}
			table.Rows = append(table.Rows, components.Row{
				{Text: s.GetSource()}, {Text: registry}, {Text: synced}, {Text: dash(s.GetSignedBy())}, {HTML: st},
			})
		}
		tables = append(tables, b.add("table", table))
	}
	return b.add("block", components.Block{
		ID: "cache-sources", Title: msg.T("verifier.cache.sources.label"), Lead: msg.T("verifier.cache.sources.lead"),
		Body: components.Join(tables...),
	})
}

// reason shortens the error of a source for its row: the row already
// names the source, and the package prefix means nothing to staff.
func reason(err, source string) string {
	err = strings.ReplaceAll(err, source, msg.T("verifier.cache.it.label"))
	for _, prefix := range []string{"ports: ", "cache: ", "trustsnap: "} {
		err = strings.TrimPrefix(err, prefix)
	}
	return err
}

// dash returns a value, or a dash word when it is empty.
func dash(v string) string {
	if v == "" {
		return msg.T("verifier.cache.none.label")
	}
	return v
}

// policyForm is the refresh intervals and the offline settings.
func (p *Portal) policyForm(r *http.Request, b *blocks, pol *policyv1.CachePolicy, problems map[string]string) template.HTML {
	refresh := components.Join(
		b.add("field", durationField("trust_refresh", msg.T("verifier.cache.trust_every.label"), pol.GetTrustListRefresh(), trustChoices, problems)),
		b.add("field", durationField("keys_refresh", msg.T("verifier.cache.keys_every.label"), pol.GetKeysRefresh(), keysChoices, problems)),
		b.add("field", durationField("status_refresh", msg.T("verifier.cache.status_every.label"), pol.GetStatusListRefresh(), statusChoices, problems)),
	)
	window := durationField("window", msg.T("verifier.cache.window.label"), pol.GetOfflineWindow(), windowChoices, problems)
	window.Hint = msg.T("verifier.cache.window.hint")
	offline := components.Join(
		b.add("choice", components.Choice{
			ID: "offline", Legend: msg.T("verifier.cache.offline.label"), Hint: msg.T("verifier.cache.offline.hint"), Multiple: true,
			Options: []components.ChoiceOption{
				{Value: boxAllowOffline, Title: msg.T("verifier.cache.allow.label"), Text: msg.T("verifier.cache.allow.text"), Checked: pol.GetAllowOffline()},
				{Value: boxMarkStale, Title: msg.T("verifier.cache.mark.label"), Text: msg.T("verifier.cache.mark.text"), Checked: pol.GetMarkStale()},
				{Value: boxRefuseStale, Title: msg.T("verifier.cache.refuse.label"), Text: msg.T("verifier.cache.refuse.text"), Checked: pol.GetRefuseStaleStatus()},
			},
		}),
		b.add("field", window),
	)
	save := b.add("button", components.Button{Text: msg.T("verifier.cache.save.label"), Type: "submit", Variant: "primary"})
	body := components.Join(
		b.add("fieldset", components.Fieldset{ID: "refresh", Legend: msg.T("verifier.cache.refresh.label"), Hint: msg.T("verifier.cache.refresh.hint"), Body: refresh}),
		b.add("fieldset", components.Fieldset{ID: "offline-set", Legend: msg.T("verifier.cache.offline_set.label"), Body: offline}),
		save,
	)
	return b.add("block", components.Block{
		ID: "cache-policy", Title: msg.T("verifier.cache.policy.label"), Lead: msg.T("verifier.cache.policy.lead"),
		Body: template.HTML(`<form method="post" action="`+template.HTMLEscapeString(p.opts.Prefix+"/cache/policy")+`">`) + //nolint:gosec // the path is escaped
			staffsession.HiddenField(r.Context()) + body + template.HTML(`</form>`),
	})
}

// durationField is a select of durations with the current value chosen.
// A current value outside the choices joins them.
func durationField(id, label string, current *durationpb.Duration, choices []time.Duration, problems map[string]string) components.Field {
	cur := current.AsDuration()
	found := false
	for _, c := range choices {
		found = found || c == cur
	}
	if !found && cur > 0 {
		choices = append(append([]time.Duration{}, choices...), cur)
	}
	opts := make([]components.Option, 0, len(choices))
	for _, c := range choices {
		opts = append(opts, components.Option{Value: shortDuration(c), Text: longDuration(c), Selected: c == cur})
	}
	return components.Field{ID: id, Label: label, Type: "select", Options: opts, Error: problems[id]}
}

// shortDuration writes a duration as whole hours or whole minutes.
func shortDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/time.Minute)) + "m"
}

// longDuration names a duration for a person.
func longDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return msg.T("verifier.cache.minutes.label", strconv.Itoa(int(d/time.Minute)))
	case d == time.Hour:
		return msg.T("verifier.cache.hour.label")
	case d%(24*time.Hour) == 0 && d > 24*time.Hour:
		return msg.T("verifier.cache.days.label", strconv.Itoa(int(d/(24*time.Hour))))
	}
	return msg.T("verifier.cache.hours.label", strconv.Itoa(int(d/time.Hour)))
}

// syncNow reads every kind, or the kind of the form, and goes back to
// the page with the outcome.
func (p *Portal) syncNow(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return p.renderCache(w, r, http.StatusBadRequest, nil, nil)
	}
	if p.opts.Cache == nil {
		return p.cacheDown(w, r)
	}
	kind := map[string]policyv1.CacheKind{
		"trust": policyv1.CacheKind_CACHE_KIND_TRUST_LIST, "keys": policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS,
		"status": policyv1.CacheKind_CACHE_KIND_STATUS_LIST,
	}[r.PostFormValue("kind")]
	res, err := p.opts.Cache.SyncCache(r.Context(), connect.NewRequest(&policyv1.SyncCacheRequest{Kind: kind}))
	if err != nil {
		return p.cacheDown(w, r)
	}
	q := url.Values{"synced": {"1"}}
	if n := res.Msg.GetFailed(); n > 0 {
		q.Set("failed", strconv.Itoa(int(n)))
	}
	http.Redirect(w, r, p.opts.Prefix+"/cache/?"+q.Encode(), http.StatusSeeOther)
	return nil
}

// cacheDown answers a post when the policy service does not answer.
func (p *Portal) cacheDown(w http.ResponseWriter, r *http.Request) error {
	return p.renderCache(w, r, http.StatusBadGateway, []components.Toast{{Level: "bad", Text: msg.T("verifier.cache.down.text")}}, nil)
}

// savePolicy stores the posted form as the cache policy.
func (p *Portal) savePolicy(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return p.renderCache(w, r, http.StatusBadRequest, nil, nil)
	}
	pol := &policyv1.CachePolicy{}
	problems := map[string]string{}
	for _, f := range []struct {
		name string
		into **durationpb.Duration
	}{
		{"trust_refresh", &pol.TrustListRefresh}, {"keys_refresh", &pol.KeysRefresh},
		{"status_refresh", &pol.StatusListRefresh}, {"window", &pol.OfflineWindow},
	} {
		raw := strings.TrimSpace(r.PostFormValue(f.name))
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			problems[f.name] = msg.T("verifier.cache.bad_time")
			continue
		}
		*f.into = durationpb.New(d)
	}
	if len(problems) > 0 {
		return p.renderCache(w, r, http.StatusUnprocessableEntity, nil, problems)
	}
	for _, box := range r.PostForm["offline"] {
		switch box {
		case boxAllowOffline:
			pol.AllowOffline = true
		case boxMarkStale:
			pol.MarkStale = true
		case boxRefuseStale:
			pol.RefuseStaleStatus = true
		}
	}
	if p.opts.Cache == nil {
		return p.cacheDown(w, r)
	}
	_, err := p.opts.Cache.SetCachePolicy(r.Context(), connect.NewRequest(&policyv1.SetCachePolicyRequest{Policy: pol}))
	switch {
	case connect.CodeOf(err) == connect.CodeInvalidArgument:
		return p.renderCache(w, r, http.StatusUnprocessableEntity,
			[]components.Toast{{Level: "bad", Text: msg.T("verifier.cache.refused", refusal(err))}}, nil)
	case err != nil:
		return p.cacheDown(w, r)
	}
	http.Redirect(w, r, p.opts.Prefix+"/cache/?saved=1", http.StatusSeeOther)
	return nil
}

// refusal returns the reason of a refused policy without the code.
func refusal(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return strings.TrimPrefix(ce.Message(), "cache: ")
	}
	return err.Error()
}

// statusWriter writes a status code before the first body byte, after
// the page set its headers.
type statusWriter struct {
	http.ResponseWriter
	code  int
	wrote bool
}

// withStatus returns w that answers with code.
func withStatus(w http.ResponseWriter, code int) http.ResponseWriter {
	if code == http.StatusOK {
		return w
	}
	return &statusWriter{ResponseWriter: w, code: code}
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.wrote = true
		s.WriteHeader(s.code)
	}
	return s.ResponseWriter.Write(b)
}

// cacheStat is the trust cache card of the overview.
func (p *Portal) cacheStat(r *http.Request) components.Stat {
	s := components.Stat{Label: msg.T("verifier.stat.cache.label"), Href: p.opts.Prefix + "/cache/"}
	state, err := p.cacheState(r.Context())
	if err != nil {
		s.Value, s.Text = msg.T("common.unknown.label"), msg.T("verifier.cache.down.text")
		return s
	}
	var oldest *policyv1.CacheKindState
	for _, k := range state.GetKinds() {
		if k.GetSyncedAt() == nil {
			continue
		}
		if oldest == nil || k.GetSyncedAt().AsTime().Before(oldest.GetSyncedAt().AsTime()) {
			oldest = k
		}
	}
	s.Value = msg.T("verifier.cache.never.label")
	if oldest != nil {
		s.Value = p.syncedValue(oldest)
	}
	s.Text = msg.T("verifier.stat.cache.off")
	if pol := state.GetPolicy(); pol.GetAllowOffline() {
		s.Text = msg.T("verifier.stat.cache.on", cards.Age(pol.GetOfflineWindow().AsDuration()))
	}
	return s
}
