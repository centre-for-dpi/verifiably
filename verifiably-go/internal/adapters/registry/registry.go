package registry

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Registry is the fan-out Adapter. Handlers see one backend.Adapter; the
// Registry routes each call to the concrete per-DPG implementation based on
// the DPG selected in the request (req.IssuerDpg / HolderDpg / VerifierDpg).
type Registry struct {
	mu sync.RWMutex

	issuers   map[string]backend.Adapter
	holders   map[string]backend.Adapter
	verifiers map[string]backend.Adapter

	issuerDPGs   map[string]vctypes.DPG
	holderDPGs   map[string]vctypes.DPG
	verifierDPGs map[string]vctypes.DPG

	// schema persistence is registry-wide — custom schemas don't belong
	// to a specific vendor. The slice is the in-memory authoritative
	// view; SchemaStore is the durable mirror written on every save /
	// delete and replayed on startup. Optional: when SchemaStore is nil
	// the Registry falls back to the original M1 behaviour (in-memory
	// only, wiped on restart) — kept that way so unit tests can build a
	// Registry without disk wiring.
	customSchemas []vctypes.Schema
	schemaStore   *SchemaStore
}

// New constructs an empty Registry. Call Register for each configured DPG.
func New() *Registry {
	return &Registry{
		issuers:      map[string]backend.Adapter{},
		holders:      map[string]backend.Adapter{},
		verifiers:    map[string]backend.Adapter{},
		issuerDPGs:   map[string]vctypes.DPG{},
		holderDPGs:   map[string]vctypes.DPG{},
		verifierDPGs: map[string]vctypes.DPG{},
	}
}

// AttachSchemaStore plugs in a SchemaStore for durable customSchemas
// persistence. Replays the file's contents into the in-memory slice
// immediately so a fresh Registry on the new build picks up where the
// previous container left off. Call once during startup, before any
// adapter is registered (so SaveCustomSchema callbacks fired during
// adapter registration would persist correctly — but those don't fire
// today; this is forward-compatible).
//
// Load errors are logged and treated as empty (caller's responsibility
// to decide loudness). Schemas with the Custom flag explicitly set to
// false are dropped — the file is meant to mirror user-built entries
// only, never stock walt.id types.
func (r *Registry) AttachSchemaStore(store *SchemaStore) error {
	if store == nil {
		return nil
	}
	loaded, err := store.Load()
	if err != nil {
		return fmt.Errorf("schema store load: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.schemaStore = store
	for _, s := range loaded {
		if !s.Custom {
			continue
		}
		r.customSchemas = append(r.customSchemas, s)
	}
	return nil
}

// IssuerSigningKey delegates to the first registered issuer adapter that
// exposes one. The status-list HTTP path needs to sign the published
// list with the same key the walt.id issuer signs credentials with;
// when verifiably-go runs in `registry` mode the handler reaches it
// through the Registry, so we proxy here. Today only the walt.id
// adapter implements this — Inji Certify and the mock adapter return
// nothing — so the first one we find is the right one.
//
// Registry doesn't statically depend on the walt.id package (would
// flip the dependency direction); we use a duck-typed interface check
// against backend.Adapter at runtime.
func (r *Registry) IssuerSigningKey(ctx context.Context) ([]byte, string, error) {
	type signer interface {
		IssuerSigningKey(ctx context.Context) ([]byte, string, error)
	}
	r.mu.RLock()
	vendors := make([]string, 0, len(r.issuers))
	for v := range r.issuers {
		vendors = append(vendors, v)
	}
	r.mu.RUnlock()
	// Sort vendors so the first signer-capable adapter is always the same
	// across calls, regardless of Go map iteration order.
	sort.Strings(vendors)
	for _, v := range vendors {
		r.mu.RLock()
		a := r.issuers[v]
		r.mu.RUnlock()
		s, ok := a.(signer)
		if !ok {
			continue
		}
		return s.IssuerSigningKey(ctx)
	}
	return nil, "", fmt.Errorf("registry: no registered issuer adapter exposes IssuerSigningKey")
}

// AllAdapters returns every distinct adapter registered across all roles.
// Used by the factory to surface concrete types for role-agnostic wiring
// (e.g. attaching per-adapter HTTP routes).
func (r *Registry) AllAdapters() []backend.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[backend.Adapter]struct{}{}
	var out []backend.Adapter
	add := func(ad backend.Adapter) {
		if _, dup := seen[ad]; dup {
			return
		}
		seen[ad] = struct{}{}
		out = append(out, ad)
	}
	for _, a := range r.issuers {
		add(a)
	}
	for _, a := range r.holders {
		add(a)
	}
	for _, a := range r.verifiers {
		add(a)
	}
	return out
}

// Register attaches an adapter for a vendor under the given roles.
// Unknown roles are silently ignored (caller should validate Config.Roles).
func (r *Registry) Register(vendor string, dpg vctypes.DPG, roles []string, ad backend.Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, role := range roles {
		switch role {
		case "issuer":
			r.issuers[vendor] = ad
			r.issuerDPGs[vendor] = dpg
		case "holder":
			r.holders[vendor] = ad
			r.holderDPGs[vendor] = dpg
		case "verifier":
			r.verifiers[vendor] = ad
			r.verifierDPGs[vendor] = dpg
		}
	}
}

// --- Adapter methods (fan-out) ---

func (r *Registry) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]vctypes.DPG, len(r.issuerDPGs))
	for k, v := range r.issuerDPGs {
		out[k] = v
	}
	return out, nil
}

func (r *Registry) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]vctypes.DPG, len(r.holderDPGs))
	for k, v := range r.holderDPGs {
		out[k] = v
	}
	return out, nil
}

func (r *Registry) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]vctypes.DPG, len(r.verifierDPGs))
	for k, v := range r.verifierDPGs {
		out[k] = v
	}
	return out, nil
}

func (r *Registry) issuerFor(vendor string) (backend.Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ad, ok := r.issuers[vendor]
	if !ok {
		return nil, fmt.Errorf("%w: issuer %q", backend.ErrUnknownDPG, vendor)
	}
	return ad, nil
}

func (r *Registry) holderFor(vendor string) (backend.Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ad, ok := r.holders[vendor]
	if !ok {
		return nil, fmt.Errorf("%w: holder %q", backend.ErrUnknownDPG, vendor)
	}
	return ad, nil
}

func (r *Registry) verifierFor(vendor string) (backend.Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ad, ok := r.verifiers[vendor]
	if !ok {
		return nil, fmt.Errorf("%w: verifier %q", backend.ErrUnknownDPG, vendor)
	}
	return ad, nil
}

func (r *Registry) ListSchemas(ctx context.Context, issuerDpg string) ([]vctypes.Schema, error) {
	ad, err := r.issuerFor(issuerDpg)
	if err != nil {
		return nil, err
	}
	// Collect in-memory custom schemas first so a vendor outage (e.g. walt.id
	// restarting itself after a SaveCustomSchema catalog edit — a self-
	// inflicted ~10s window) doesn't make the browser look empty. The handler
	// renders whatever we return; on partial success it shows the custom
	// schemas plus a transient-error banner instead of a blank page or, worse,
	// an http.Error body bleeding into the rendered HTML.
	//
	// Per-issuer scoping: filter the in-memory slice by the caller's
	// IssuerIdentity (set via backend.WithIssuerIdentity in the handler
	// layer). When the caller has no identity attached (admin / CLI),
	// every custom schema passes through. The vendor-side ListSchemas
	// (walt.id's wellknown) is global — there's no per-issuer view at
	// the walt.id container — so vendor schemas remain shared. That's
	// intentional: stock catalog entries are common to all issuers; only
	// user-saved schemas are private.
	owner := backend.IssuerIdentityFromContext(ctx)
	r.mu.RLock()
	custom := make([]vctypes.Schema, 0, len(r.customSchemas))
	for _, s := range r.customSchemas {
		if owner != "" && s.OwnerKey != "" && s.OwnerKey != owner {
			continue
		}
		for _, d := range s.DPGs {
			if d == issuerDpg {
				custom = append(custom, s)
				break
			}
		}
	}
	r.mu.RUnlock()
	vendorSchemas, vendorErr := ad.ListSchemas(ctx, issuerDpg)
	if vendorErr != nil {
		// Return the custom schemas we already gathered alongside the vendor
		// error. Caller decides whether to surface (handler shows a banner;
		// strict callers can treat err != nil as a hard failure).
		return custom, vendorErr
	}
	// The walt.id wellknown returns ALL configurationIds in the
	// catalog, including custom-schema entries from other issuers
	// (their type names leak via /.well-known/openid-credential-issuer
	// — that's a walt.id property we can't fix in-process). Suppress
	// vendor entries whose ID matches a custom schema we know belongs
	// to another owner. Stock vendor entries (no matching custom row)
	// pass through normally.
	if owner != "" {
		r.mu.RLock()
		hideIDs := map[string]struct{}{}
		for _, s := range r.customSchemas {
			if s.OwnerKey != "" && s.OwnerKey != owner {
				hideIDs[s.ID] = struct{}{}
				for _, v := range s.Variants {
					hideIDs[v.ID] = struct{}{}
				}
			}
		}
		r.mu.RUnlock()
		if len(hideIDs) > 0 {
			filtered := vendorSchemas[:0]
			for _, s := range vendorSchemas {
				if _, hide := hideIDs[s.ID]; hide {
					continue
				}
				filtered = append(filtered, s)
			}
			vendorSchemas = filtered
		}
	}
	return append(vendorSchemas, custom...), nil
}

func (r *Registry) ListAllSchemas(ctx context.Context) ([]vctypes.Schema, error) {
	owner := backend.IssuerIdentityFromContext(ctx)
	r.mu.RLock()
	vendors := make([]string, 0, len(r.issuers))
	for v := range r.issuers {
		vendors = append(vendors, v)
	}
	custom := make([]vctypes.Schema, 0, len(r.customSchemas))
	hideIDs := map[string]struct{}{}
	for _, s := range r.customSchemas {
		if owner != "" && s.OwnerKey != "" && s.OwnerKey != owner {
			// Foreign custom schema — exclude it AND remember its ids to
			// suppress when they show up via vendor wellknown below.
			hideIDs[s.ID] = struct{}{}
			for _, v := range s.Variants {
				hideIDs[v.ID] = struct{}{}
			}
			continue
		}
		custom = append(custom, s)
	}
	r.mu.RUnlock()

	seen := map[string]struct{}{}
	var out []vctypes.Schema
	for _, v := range vendors {
		ad, _ := r.issuerFor(v)
		sch, err := ad.ListSchemas(ctx, v)
		if err != nil {
			// Log and continue rather than fail-fast: a fresh stack often
			// has one DPG still warming up when the operator reaches the
			// issue screen, and taking the whole aggregated list down
			// because Inji Certify is unhealthy (for example) blocks walt.id
			// flows that have nothing to do with it. Callers that need
			// per-DPG precision should use ListSchemas(ctx, vendor) directly.
			slog.Warn("registry: ListSchemas failed, skipping", "vendor", v, "err", err)
			continue
		}
		for _, s := range sch {
			if _, dup := seen[s.ID]; dup {
				continue
			}
			if _, hide := hideIDs[s.ID]; hide {
				continue
			}
			seen[s.ID] = struct{}{}
			out = append(out, s)
		}
	}
	out = append(out, custom...)
	return out, nil
}

func (r *Registry) SaveCustomSchema(ctx context.Context, schema vctypes.Schema) error {
	r.mu.Lock()
	schema.Custom = true
	// Stamp the saving issuer's identity onto the schema so subsequent
	// ListSchemas calls only return it to the same issuer's session.
	// Empty key (admin/CLI flow) leaves the schema globally visible so
	// migration tooling and shared-demo modes still work.
	if owner := backend.IssuerIdentityFromContext(ctx); owner != "" {
		schema.OwnerKey = owner
	}
	r.customSchemas = append(r.customSchemas, schema)
	store := r.schemaStore
	// Snapshot the issuer adapters that own the schema's DPGs so we can
	// hand them the save without holding r.mu (the adapter's own callback
	// may take seconds — restartContainer waits for the issuer-api to
	// come back up).
	dispatch := make([]backend.Adapter, 0, len(schema.DPGs))
	for _, vendor := range schema.DPGs {
		if ad, ok := r.issuers[vendor]; ok {
			dispatch = append(dispatch, ad)
		}
	}
	r.mu.Unlock()
	// Persist BEFORE the adapter callback. The adapter's callback may
	// take seconds (restartContainer waits for issuer-api to come back
	// up) — pinning the on-disk state first means a crash mid-callback
	// still leaves the schema recoverable on next boot.
	if store != nil {
		if _, err := store.Upsert(schema); err != nil {
			return fmt.Errorf("persist schema: %w", err)
		}
	}
	for _, ad := range dispatch {
		if err := ad.SaveCustomSchema(ctx, schema); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) DeleteCustomSchema(ctx context.Context, id string) error {
	r.mu.Lock()
	idx := -1
	for i, s := range r.customSchemas {
		if s.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		r.mu.Unlock()
		return fmt.Errorf("custom schema %q not found", id)
	}
	// Owner check: a non-owner can't delete via id-guess. Surfaced as
	// not-found so the existence isn't disclosed. Empty owner key
	// (admin) bypasses, mirroring SaveCustomSchema.
	owner := backend.IssuerIdentityFromContext(ctx)
	if owner != "" && r.customSchemas[idx].OwnerKey != "" && r.customSchemas[idx].OwnerKey != owner {
		r.mu.Unlock()
		return fmt.Errorf("custom schema %q not found", id)
	}
	removed := r.customSchemas[idx]
	r.customSchemas = append(r.customSchemas[:idx], r.customSchemas[idx+1:]...)
	store := r.schemaStore
	dispatch := make([]backend.Adapter, 0, len(removed.DPGs))
	for _, vendor := range removed.DPGs {
		if ad, ok := r.issuers[vendor]; ok {
			dispatch = append(dispatch, ad)
		}
	}
	r.mu.Unlock()
	// Persist the removal BEFORE the adapter callback for the same
	// reason we persist the save before its callback: a crash during
	// the slow walt.id restart loop should leave on-disk state already
	// reflecting what the operator asked for.
	if store != nil {
		if _, _, err := store.Remove(id); err != nil {
			return fmt.Errorf("persist schema removal: %w", err)
		}
	}
	for _, ad := range dispatch {
		if err := ad.DeleteCustomSchema(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) PrefillSubjectFields(ctx context.Context, schema vctypes.Schema) (map[string]string, error) {
	// Prefill is a per-issuer operation; dispatch to whichever issuer claims
	// the schema. Custom schemas — not owned by a vendor — return empty.
	if schema.Custom {
		return map[string]string{}, nil
	}
	for _, vendor := range schema.DPGs {
		ad, err := r.issuerFor(vendor)
		if err == nil {
			return ad.PrefillSubjectFields(ctx, schema)
		}
	}
	return map[string]string{}, nil
}

func (r *Registry) IssueToWallet(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	ad, err := r.issuerFor(req.IssuerDpg)
	if err != nil {
		return backend.IssueToWalletResult{}, err
	}
	return ad.IssueToWallet(ctx, req)
}

func (r *Registry) IssueAsPDF(ctx context.Context, req backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	ad, err := r.issuerFor(req.IssuerDpg)
	if err != nil {
		return backend.IssueAsPDFResult{}, err
	}
	return ad.IssueAsPDF(ctx, req)
}

func (r *Registry) IssueBulk(ctx context.Context, req backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	ad, err := r.issuerFor(req.IssuerDpg)
	if err != nil {
		return backend.IssueBulkResult{}, err
	}
	return ad.IssueBulk(ctx, req)
}

// currentHolder returns the adapter for the holder DPG attached to ctx via
// WithHolderDpg. If ctx has no holder and exactly one holder is registered,
// that holder is the default (so a single-DPG deploy doesn't need handlers
// to wrap every call). If ctx has no holder and multiple are registered,
// the call is ambiguous and we error — handlers MUST wrap when running in
// scenario=all.
func (r *Registry) currentHolder(ctx context.Context) (backend.Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if vendor := backend.HolderDpgFromContext(ctx); vendor != "" {
		if ad, ok := r.holders[vendor]; ok {
			return ad, nil
		}
		return nil, fmt.Errorf("%w: holder %q not registered", backend.ErrUnknownDPG, vendor)
	}
	if len(r.holders) == 1 {
		for _, ad := range r.holders {
			return ad, nil
		}
	}
	return nil, fmt.Errorf("%w: holder not selected", backend.ErrUnknownDPG)
}

func (r *Registry) ListWalletCredentials(ctx context.Context) ([]vctypes.Credential, error) {
	ad, err := r.currentHolder(ctx)
	if err != nil {
		// No holders configured yet — empty list beats a crash.
		return []vctypes.Credential{}, nil
	}
	return ad.ListWalletCredentials(ctx)
}

func (r *Registry) DeleteWalletCredential(ctx context.Context, credentialID string) error {
	ad, err := r.currentHolder(ctx)
	if err != nil {
		return err
	}
	return ad.DeleteWalletCredential(ctx, credentialID)
}

func (r *Registry) ListExampleOffers(ctx context.Context) ([]string, error) {
	// Aggregate live bootstrap offers across all registered issuer adapters.
	r.mu.RLock()
	ads := make([]backend.Adapter, 0, len(r.issuers))
	for _, ad := range r.issuers {
		ads = append(ads, ad)
	}
	r.mu.RUnlock()

	var all []string
	for _, ad := range ads {
		offs, err := ad.BootstrapOffers(ctx)
		if err != nil {
			continue
		}
		all = append(all, offs...)
	}
	return all, nil
}

func (r *Registry) ParseOffer(ctx context.Context, offerURI string) (vctypes.Credential, error) {
	ad, err := r.currentHolder(ctx)
	if err != nil {
		return vctypes.Credential{}, err
	}
	return ad.ParseOffer(ctx, offerURI)
}

func (r *Registry) ClaimCredential(ctx context.Context, cred vctypes.Credential) (vctypes.Credential, error) {
	ad, err := r.currentHolder(ctx)
	if err != nil {
		return vctypes.Credential{}, err
	}
	return ad.ClaimCredential(ctx, cred)
}

func (r *Registry) PresentCredential(ctx context.Context, req backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	ad, err := r.holderFor(req.HolderDpg)
	if err != nil {
		return backend.PresentCredentialResult{}, err
	}
	return ad.PresentCredential(ctx, req)
}

// PreviewPresentation routes to the holder adapter's optional
// backend.PresentationPreviewer implementation. Registry implements the
// interface so handlers that use the registry as backend.Adapter see the
// capability transparently; adapters that don't support preview get a
// zero-value response rather than an error, mirroring the fallback path
// in the handler.
func (r *Registry) PreviewPresentation(ctx context.Context, req backend.PresentCredentialRequest) (backend.PresentationPreview, error) {
	ad, err := r.holderFor(req.HolderDpg)
	if err != nil {
		return backend.PresentationPreview{}, err
	}
	if p, ok := ad.(backend.PresentationPreviewer); ok {
		return p.PreviewPresentation(ctx, req)
	}
	return backend.PresentationPreview{CredentialID: req.CredentialID}, nil
}

func (r *Registry) BootstrapOffers(ctx context.Context) ([]string, error) {
	return r.ListExampleOffers(ctx)
}

func (r *Registry) ListOID4VPTemplates(ctx context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	// Aggregate: merge each verifier's templates into one map, keyed by vendor
	// prefix so different verifiers' templates don't collide.
	r.mu.RLock()
	ads := make(map[string]backend.Adapter, len(r.verifiers))
	for v, ad := range r.verifiers {
		ads[v] = ad
	}
	r.mu.RUnlock()

	out := map[string]vctypes.OID4VPTemplate{}
	for vendor, ad := range ads {
		tpl, err := ad.ListOID4VPTemplates(ctx)
		if err != nil {
			continue
		}
		for k, v := range tpl {
			// Prefix with the vendor name so templates from different adapters
			// (e.g. "waltid:age-verification" vs "credebl:age-verification")
			// never silently overwrite each other in the merged map.
			key := vendor + ":" + k
			if _, dup := out[key]; dup {
				continue
			}
			out[key] = v
		}
	}
	return out, nil
}

func (r *Registry) RequestPresentation(ctx context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	ad, err := r.verifierFor(req.VerifierDpg)
	if err != nil {
		return backend.PresentationRequestResult{}, err
	}
	// Strip the vendor prefix from TemplateKey when the caller passes back a
	// key obtained from this registry's ListOID4VPTemplates — those keys are
	// prefixed "vendor:original" to prevent cross-adapter collisions. The
	// adapter only knows its own bare key ("original"), not the registry key.
	if inner, ok := strings.CutPrefix(req.TemplateKey, req.VerifierDpg+":"); ok {
		req.TemplateKey = inner
	}
	res, err := ad.RequestPresentation(ctx, req)
	if err != nil {
		return res, err
	}
	// Tag the state with the vendor DPG using a pipe-delimited prefix so
	// FetchPresentationResult can route back to the same adapter without an
	// interface change. Format: "dpg|<vendor>|<inner-state>".
	// Pipe is used instead of colon because vendor IDs are DIDs
	// (e.g. did:web:...) which themselves contain colons.
	res.State = "dpg|" + req.VerifierDpg + "|" + res.State
	return res, nil
}

func (r *Registry) FetchPresentationResult(ctx context.Context, state, templateKey string) (backend.VerificationResult, error) {
	// The state is tagged with the vendor DPG by RequestPresentation above.
	// Format: "dpg|<vendor>|<inner-state>". Parse and route deterministically;
	// fall back to first-adapter for any untagged state (legacy sessions or
	// single-vendor deployments that never went through this registry).
	if after, ok := strings.CutPrefix(state, "dpg|"); ok {
		vendor, inner, _ := strings.Cut(after, "|")
		ad, err := r.verifierFor(vendor)
		if err != nil {
			return backend.VerificationResult{}, err
		}
		return ad.FetchPresentationResult(ctx, inner, templateKey)
	}
	// Legacy path: no tag — only safe for single-verifier deployments.
	// With multiple verifiers, we cannot deterministically pick one; fail fast
	// so the caller knows to re-initiate the verification flow.
	r.mu.RLock()
	ads := make([]backend.Adapter, 0, len(r.verifiers))
	for _, ad := range r.verifiers {
		ads = append(ads, ad)
	}
	r.mu.RUnlock()
	if len(ads) == 0 {
		return backend.VerificationResult{}, fmt.Errorf("%w: no verifier configured", backend.ErrUnknownDPG)
	}
	if len(ads) > 1 {
		return backend.VerificationResult{}, fmt.Errorf("verification session predates multi-vendor routing; please re-initiate the verification flow")
	}
	return ads[0].FetchPresentationResult(ctx, state, templateKey)
}

func (r *Registry) VerifyDirect(ctx context.Context, req backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	ad, err := r.verifierFor(req.VerifierDpg)
	if err != nil {
		return backend.VerificationResult{}, err
	}
	return ad.VerifyDirect(ctx, req)
}

// Compile-time check: Registry satisfies backend.Adapter.
var _ backend.Adapter = (*Registry)(nil)
