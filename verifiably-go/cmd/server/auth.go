package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/internal/auth/oidc"
	"github.com/verifiably/verifiably-go/internal/handlers"
)

// authSystemProvidersFile points at the deploy-managed bootstrap file
// (Keycloak + WSO2IS demo defaults written by deploy.sh's auth_providers_for).
// Override via VERIFIABLY_AUTH_PROVIDERS_FILE — kept on the legacy env name
// so existing operator setups don't break.
//
// Resolution order:
//  1. VERIFIABLY_AUTH_PROVIDERS_FILE (explicit override)
//  2. config/auth-providers.system.json (preferred new path)
//  3. config/auth-providers.json        (legacy path; still written by older deploy.sh)
//
// The legacy path is the second fallback so a half-upgraded deployment
// (new binary, old deploy.sh) keeps booting until the operator re-runs
// the script. Once auth-providers.system.json exists the legacy file is
// ignored — no double-load, no merge surprises.
func authSystemProvidersFile() string {
	if v := os.Getenv("VERIFIABLY_AUTH_PROVIDERS_FILE"); v != "" {
		return v
	}
	if _, err := os.Stat("config/auth-providers.system.json"); err == nil {
		return "config/auth-providers.system.json"
	}
	return "config/auth-providers.json"
}

// authUserProvidersFile points at the runtime, admin-UI-managed file that
// survives ./deploy.sh re-runs. Created on first POST to /admin/auth-providers.
// Override via VERIFIABLY_AUTH_USER_PROVIDERS_FILE.
func authUserProvidersFile() string {
	if v := os.Getenv("VERIFIABLY_AUTH_USER_PROVIDERS_FILE"); v != "" {
		return v
	}
	return "config/auth-providers.user.json"
}

// loadProviderConfigs returns the merged OIDC provider configs. Layered:
//
//  1. VERIFIABLY_OIDC_PROVIDERS — JSON array passed as a single env var.
//     When set, replaces both files entirely (highest precedence). Use this
//     for IaC / Helm / Compose deploys that own their IdP config in env.
//
//  2. auth-providers.system.json (deploy.sh-managed bootstrap, e.g. the
//     Keycloak + WSO2IS demo defaults). Loaded as base layer.
//
//  3. auth-providers.user.json (admin-UI-managed, persists across deploy
//     runs). Merged on top: a user entry with the same id overrides the
//     system entry, anything new gets appended.
//
//  4. Per-field env overrides VERIFIABLY_OIDC_<ID>_{ISSUER_URL,CLIENT_ID,
//     CLIENT_SECRET,DISPLAY_NAME,SCOPES,INSECURE_SKIP_VERIFY} — applied
//     AFTER the file merge so a single secret rotation doesn't require
//     hand-editing JSON.
//
// Each returned config carries .Source ("system"|"user"|"env") so the
// admin UI can decide which rows are deletable. Returns (cfgs, label)
// where label summarises the inputs for the startup log line.
func loadProviderConfigs() ([]auth.ProviderConfig, string) {
	if raw := os.Getenv("VERIFIABLY_OIDC_PROVIDERS"); strings.TrimSpace(raw) != "" {
		var cfgs []auth.ProviderConfig
		if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
			log.Fatalf("auth: VERIFIABLY_OIDC_PROVIDERS is set but not valid JSON: %v", err)
		}
		for i := range cfgs {
			cfgs[i].Source = auth.SourceEnv
		}
		return applyEnvOverrides(cfgs), "VERIFIABLY_OIDC_PROVIDERS env"
	}
	system := readProvidersFile(authSystemProvidersFile(), auth.SourceSystem)
	user := readProvidersFile(authUserProvidersFile(), auth.SourceUser)
	merged := mergeProviders(system, user)
	if len(merged) == 0 {
		return applyEnvOverrides(nil), "demo (no providers)"
	}
	return applyEnvOverrides(merged), describeSources(system, user)
}

// readProvidersFile reads one auth-providers JSON file and tags every
// entry with the given source label. Missing file → empty slice (not an
// error, since either file is allowed to be absent). Unparseable file →
// fatal — corrupt config should fail the boot, not silently drop rows.
func readProvidersFile(path, source string) []auth.ProviderConfig {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		// Empty file is treated as []. Tolerated so deploy.sh's
		// VERIFIABLY_NO_DEFAULT_IDPS path can write an empty list
		// without us having to special-case zero-byte files.
		return nil
	}
	var cfgs []auth.ProviderConfig
	if err := json.Unmarshal(b, &cfgs); err != nil {
		log.Fatalf("auth: parse %s: %v", path, err)
	}
	for i := range cfgs {
		cfgs[i].Source = source
	}
	return cfgs
}

// mergeProviders applies user-wins-on-id-collision merge: the result starts
// with system, then for every user entry replaces a same-id row in place
// (preserving order) or appends. Insertion order matters for the auth
// page tile layout — system tiles stay where the operator first saw them.
func mergeProviders(system, user []auth.ProviderConfig) []auth.ProviderConfig {
	out := make([]auth.ProviderConfig, len(system))
	copy(out, system)
	for _, u := range user {
		replaced := false
		for i, existing := range out {
			if existing.ID == u.ID {
				out[i] = u
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, u)
		}
	}
	return out
}

// describeSources renders a one-line summary of which files contributed,
// for the startup log. "system+user(2)" reads better than two separate
// log lines, especially when an operator is debugging why a provider
// they thought they removed keeps coming back.
func describeSources(system, user []auth.ProviderConfig) string {
	parts := []string{}
	if n := len(system); n > 0 {
		parts = append(parts, fmt.Sprintf("system(%d)", n))
	}
	if n := len(user); n > 0 {
		parts = append(parts, fmt.Sprintf("user(%d)", n))
	}
	if len(parts) == 0 {
		return "demo (no providers)"
	}
	return strings.Join(parts, "+")
}

// applyEnvOverrides layers per-provider scalar env vars on top of an already-
// loaded config slice. Walks each provider, looks up VERIFIABLY_OIDC_<ID>_*
// env vars, and overrides the matching fields when set. Untouched fields
// keep their loaded value, so an operator can override only what changed
// (typically issuerUrl + client secret) without re-declaring the rest.
func applyEnvOverrides(cfgs []auth.ProviderConfig) []auth.ProviderConfig {
	for i, c := range cfgs {
		prefix := "VERIFIABLY_OIDC_" + envSafeID(c.ID) + "_"
		if v := os.Getenv(prefix + "ISSUER_URL"); v != "" {
			cfgs[i].IssuerURL = v
		}
		if v := os.Getenv(prefix + "PUBLIC_ISSUER_URL"); v != "" {
			cfgs[i].PublicIssuerURL = v
		}
		if v := os.Getenv(prefix + "CLIENT_ID"); v != "" {
			cfgs[i].ClientID = v
		}
		if v := os.Getenv(prefix + "CLIENT_SECRET"); v != "" {
			cfgs[i].ClientSecret = v
		}
		if v := os.Getenv(prefix + "DISPLAY_NAME"); v != "" {
			cfgs[i].DisplayName = v
		}
		if v := os.Getenv(prefix + "KIND"); v != "" {
			cfgs[i].Kind = v
		}
		if v := os.Getenv(prefix + "SCOPES"); v != "" {
			cfgs[i].Scopes = splitCSV(v)
		}
		if v := os.Getenv(prefix + "INSECURE_SKIP_VERIFY"); v != "" {
			cfgs[i].InsecureSkipVerify = v == "1" || strings.EqualFold(v, "true")
		}
	}
	return cfgs
}

// envSafeID upper-cases an id and replaces non-alphanumerics with "_" so
// "my-idp" → "MY_IDP" and slots safely into a VERIFIABLY_OIDC_<ID>_<FIELD>
// env-var name.
func envSafeID(id string) string {
	var b strings.Builder
	b.Grow(len(id))
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// splitCSV trims whitespace around each comma-separated entry; empty
// entries are dropped so a trailing comma doesn't produce a blank scope.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// buildAuthUserStore returns the *auth.UserStore that persists OIDC
// providers added via /auth/custom. Wired in every admin mode — even
// when VERIFIABLY_AUTH_ADMIN=off, persistence stays available so
// hiding the admin surface never silently turns a working /auth/custom
// into an in-memory-only sink. Also runs the one-shot migration for
// operators upgrading from the .bak workaround.
func buildAuthUserStore() *auth.UserStore {
	store := auth.NewUserStore(authUserProvidersFile())
	migrateLegacyAuthBackup(store)
	return store
}

// migrateLegacyAuthBackup transparently imports a pre-existing
// auth-providers.docker.json.bak into the new user-managed file.
//
// History: before split-file persistence existed, operators preserved
// custom providers (e.g. the Bootcamp Client OIDC config) by copying
// auth-providers.docker.json into a sibling .bak before each ./deploy.sh
// run, then restoring it. Now that user.json survives reruns natively,
// the .bak is obsolete.
//
// This migration:
//   - Runs only when user.json is missing AND a .bak exists.
//   - Picks entries that look like user additions: any provider whose id
//     isn't in the system-managed file (Keycloak, WSO2IS).
//   - On success, renames the .bak to .bak.migrated so it can't trigger
//     a second time (and so the operator can verify the contents post-
//     migration if anything looks off).
//
// Failure modes are silent — log and continue. Worst case the operator
// re-creates their entries via the new admin UI.
func migrateLegacyAuthBackup(store *auth.UserStore) {
	const legacyBak = "config/auth-providers.docker.json.bak"
	if existing, err := store.Load(); err == nil && len(existing) > 0 {
		return // user.json already populated — nothing to do
	}
	bakBytes, err := os.ReadFile(legacyBak)
	if err != nil {
		return // no .bak — nothing to migrate
	}
	var bak []auth.ProviderConfig
	if err := json.Unmarshal(bakBytes, &bak); err != nil {
		log.Printf("auth: skipping legacy %s — unparseable: %v", legacyBak, err)
		return
	}
	systemIDs := map[string]bool{}
	for _, c := range readProvidersFile(authSystemProvidersFile(), auth.SourceSystem) {
		systemIDs[c.ID] = true
	}
	imported := bak[:0]
	for _, c := range bak {
		if !systemIDs[c.ID] {
			imported = append(imported, c)
		}
	}
	if len(imported) == 0 {
		return
	}
	if err := store.Save(imported); err != nil {
		log.Printf("auth: legacy migration failed: %v", err)
		return
	}
	migrated := legacyBak + ".migrated"
	if err := os.Rename(legacyBak, migrated); err != nil {
		log.Printf("auth: imported %d legacy provider(s) but couldn't rename %s: %v", len(imported), legacyBak, err)
		return
	}
	log.Printf("auth: migrated %d provider(s) from %s → %s (renamed to %s)", len(imported), legacyBak, store.Path(), migrated)
}

// authAdminMode returns the normalised value of VERIFIABLY_AUTH_ADMIN.
// Default: "rw". Anything else passes through unchanged so the handler
// layer can decide ro / off semantics.
func authAdminMode() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("VERIFIABLY_AUTH_ADMIN")))
	switch v {
	case "ro", "off":
		return v
	case "rw", "":
		return "rw"
	default:
		log.Printf("auth: unknown VERIFIABLY_AUTH_ADMIN=%q — defaulting to rw", v)
		return "rw"
	}
}

// buildAuthRegistry loads providers (env first, then file) and returns a
// registry. Missing config → empty registry (no-OIDC demo mode).
func buildAuthRegistry() *auth.Registry {
	reg := auth.NewRegistry()
	cfgs, source := loadProviderConfigs()
	if len(cfgs) == 0 {
		log.Printf("auth: no providers configured (source=%s)", source)
		return reg
	}
	for _, c := range cfgs {
		switch c.Type {
		case "oidc", "":
			p, err := oidc.New(oidc.Config{
				ID:                 c.ID,
				DisplayName:        c.DisplayName,
				Kind:               c.Kind,
				IssuerURL:          c.IssuerURL,
				PublicIssuerURL:    c.PublicIssuerURL,
				ClientID:           c.ClientID,
				ClientSecret:       c.ClientSecret,
				Scopes:             c.Scopes,
				InsecureSkipVerify: c.InsecureSkipVerify,
				Source:             c.Source,
			})
			if err != nil {
				log.Fatalf("auth: build %q: %v", c.ID, err)
			}
			reg.Register(p)
			log.Printf("auth: registered provider %q (type=oidc, issuer=%s, source=%s)", c.ID, c.IssuerURL, source)
		default:
			log.Printf("auth: unknown provider type %q — skipping %q", c.Type, c.ID)
		}
	}
	return reg
}

// wireAuthHelpers swaps out the indirection hooks used by handlers to get a
// random state, PKCE verifier, and runtime custom-provider builder.
// Separated here so handlers/ stays free of imports from the oidc
// subpackage.
//
// The build hook backing /auth/custom is just oidc.New wrapped to take
// the handler-package's CustomProviderInput shape — coreos/go-oidc's
// NewProvider does the OIDC discovery, so any URL that doesn't serve
// /.well-known/openid-configuration fails fast inside oidc.New() and the
// handler surfaces the error verbatim as a toast.
func wireAuthHelpers() {
	build := func(_ context.Context, in handlers.CustomProviderInput) (auth.Provider, error) {
		// Source defaults to "runtime" when in.Source is empty (legacy
		// /auth/custom callers); admin-UI callers pass auth.SourceUser
		// explicitly so the resulting registry entry shows up as
		// editable/deletable instead of the generic in-memory tile.
		source := in.Source
		if source == "" {
			source = auth.SourceRuntime
		}
		return oidc.New(oidc.Config{
			ID:                 in.ID,
			DisplayName:        in.DisplayName,
			Kind:               "OIDC",
			IssuerURL:          in.IssuerURL,
			ClientID:           in.ClientID,
			ClientSecret:       in.ClientSecret,
			Scopes:             in.Scopes,
			InsecureSkipVerify: in.InsecureSkipVerify,
			Source:             source,
		})
	}
	handlers.SetOIDCHelpers(oidc.NewState, oidc.NewPKCEVerifier, build)
}
