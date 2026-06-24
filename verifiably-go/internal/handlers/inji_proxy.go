package handlers

// inji_proxy.go — minimal OID4VCI credential-request proxy for Inji Certify.
//
// Why this exists: certify-nginx (deploy/compose/stack/inji/certify-nginx/
// nginx.conf) routes POST /v1/certify/issuance/credential to
// http://host.docker.internal:8080/inji-proxy/issuance/credential. That's our
// port. When the route doesn't resolve, Mimoto fails the credential download
// with a 404, and Inji Web shows "An Error Occurred — unable to download the
// card". So we expose the endpoint and forward to inji-certify directly.
//
// We ALSO inject `credential_definition.@context` if the wallet omitted it —
// Inji Certify's LdpVcCredentialRequestValidator rejects w3c_vcdm_2 requests
// without an @context array, and some wallets (walt.id in particular) don't
// send one. Mimoto usually includes it; the injection is a no-op for them.
//
// The did.json handlers below are the second reason we need this proxy: Inji
// Certify v0.14.0 publishes did:web:…#<kid_A> in its did.json but signs VCs
// with did:web:…#<kid_B> — both derivations of the same Ed25519 key. Inji
// Verify's DidWebPublicKeyResolver strictly matches kid, so verification
// fails. We watch outgoing VC responses, extract whatever kid appears in the
// signature, and add it to the did.json we serve — as many aliases as
// needed, all mapped to the upstream publicKeyMultibase.
//
// TWO did.json handlers, one per Inji Certify instance:
//   - InjiProxyPrimaryDidJSON at /inji-proxy/.well-known/did.json
//     Serves did:web:certify-nginx → auth-code (primary) instance's keys.
//   - InjiProxyPreauthDidJSON at /inji-proxy-preauth/.well-known/did.json
//     Serves did:web:certify-preauth-nginx → pre-auth instance's keys.
// Each handler fetches ONLY its own instance's upstream did.json and
// patches in ONLY kids observed on that instance. No merge, no ordering,
// no collision. The two instances issue under distinct DIDs so their
// verification paths never cross.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/verifiably/verifiably-go/internal/injidid"
)

func injiCertifyUpstream() string {
	if v := os.Getenv("INJI_CERTIFY_UPSTREAM_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	// Default matches the docker-compose service name, since this handler
	// runs inside the verifiably-go container sharing the waltid_default
	// network.
	return "http://inji-certify:8090"
}

// injiCertifyPreauthUpstream points at the pre-auth instance's backend.
// The public-facing `inji-certify-preauth` container is actually the
// preauth-proxy sidecar; the real backend sits behind it as
// `inji-certify-preauth-backend`. did.json fetches go direct to the
// backend because the sidecar doesn't implement that route.
func injiCertifyPreauthUpstream() string {
	if v := os.Getenv("INJI_CERTIFY_PREAUTH_UPSTREAM_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://inji-certify-preauth-backend:8090"
}

// InjiProxyCredential forwards a POST to Inji Certify's issuance/credential
// endpoint, patching in @context if the wallet omitted it. Also records any
// kid that appears in the signed VC into the PRIMARY observer — this route
// only ever forwards to the auth-code (primary) instance.
func (h *H) InjiProxyCredential(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if patched, ok := injectCredentialContext(body); ok {
		body = patched
	}

	upstream := injiCertifyUpstream() + "/v1/certify/issuance/credential"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "build upstream request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if ah := r.Header.Get("Authorization"); ah != "" {
		req.Header.Set("Authorization", ah)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("inji-proxy: upstream error: %v", err)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		log.Printf("inji-proxy: credential RESP %d body=%s", resp.StatusCode, truncateForLog(string(respBody), 400))
	} else {
		injidid.Primary.Remember(respBody)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// InjiProxyStatusList forwards a GET to Inji Certify's bitstring status-list
// credential endpoint. We tap it so the primary observer sees the kid that
// signed the status-list VC — Inji Certify v0.14.0 derives that kid
// differently from the one on regular VCs. Both are the SAME Ed25519 key,
// but Inji Verify's strict kid-matching fails on the status-list unless our
// did.json advertises both. Only targets the primary instance; pre-auth
// has no separate status-list we proxy.
func (h *H) InjiProxyStatusList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	upstream := injiCertifyUpstream() + "/v1/certify/credentials/status-list/" + id
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream, nil)
	if err != nil {
		http.Error(w, "build upstream request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 400 {
		injidid.Primary.Remember(body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// InjiProxyWellKnown serves the OID4VCI issuer metadata for the auth-code
// (primary) Inji Certify instance. certify-nginx proxies
// GET /.well-known/openid-credential-issuer here (to host.docker.internal:8080/
// inji-proxy/...); without this route Mimoto/Inji Web get a 404 on metadata
// discovery and the card download fails before issuance even starts.
//
// Pass-through by design: the upstream is injiCertifyUpstream() (env
// INJI_CERTIFY_UPSTREAM_URL, default the docker service name) and the metadata's
// own URLs are emitted by Inji Certify from its config — so this is
// host-agnostic and works unchanged on localhost or any deployed host. We don't
// rewrite the body: the auth-code consumers (Mimoto, Credo) accept Certify's
// native metadata, unlike the pre-auth/walt.id path which needs sanitising.
func (h *H) InjiProxyWellKnown(w http.ResponseWriter, r *http.Request) {
	upstream := injiCertifyUpstream() + "/v1/certify/.well-known/openid-credential-issuer"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream, nil)
	if err != nil {
		http.Error(w, "build upstream request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("inji-proxy: wellknown upstream error: %v", err)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		log.Printf("inji-proxy: wellknown RESP %d body=%s", resp.StatusCode, truncateForLog(string(body), 400))
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// InjiProxyPrimaryDidJSON serves /.well-known/did.json for did:web:certify-nginx.
// Fetches the PRIMARY (auth-code) Inji Certify instance's own did.json and
// patches verificationMethod with every kid we've seen the primary sign
// with. Does NOT touch the pre-auth instance — its keys live under a
// separate DID and a separate handler.
func (h *H) InjiProxyPrimaryDidJSON(w http.ResponseWriter, r *http.Request) {
	doc, status, err := fetchDidJSON(r.Context(), injiCertifyUpstream()+"/v1/certify/.well-known/did.json")
	if err != nil || status != http.StatusOK {
		log.Printf("inji-proxy: primary did.json upstream status=%d err=%v", status, err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	patchedDidDoc(doc, injidid.Primary.Snapshot())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// InjiProxyPreauthDidJSON serves /.well-known/did.json for
// did:web:certify-preauth-nginx. Fetches the PRE-AUTH Inji Certify
// instance's own did.json and patches verificationMethod with every kid
// we've seen the pre-auth instance sign with. Fully independent of the
// primary handler — no merge, no ordering, no ambient kid-collision
// risk.
func (h *H) InjiProxyPreauthDidJSON(w http.ResponseWriter, r *http.Request) {
	doc, status, err := fetchDidJSON(r.Context(), injiCertifyPreauthUpstream()+"/v1/certify/.well-known/did.json")
	if err != nil || status != http.StatusOK {
		log.Printf("inji-proxy: preauth did.json upstream status=%d err=%v", status, err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	patchedDidDoc(doc, injidid.Preauth.Snapshot())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// fetchDidJSON GETs the upstream did.json, returns the parsed doc + status.
// Shared by both Primary and Preauth handlers — the ONLY shared helper.
func fetchDidJSON(ctx context.Context, url string) (map[string]any, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, resp.StatusCode, err
	}
	return doc, resp.StatusCode, nil
}

// patchedDidDoc mutates doc to add one verificationMethod per extra kid,
// cloning the upstream method's key material. The original method stays in
// place (some verifiers cache on first match). `extras` is allowed to include
// kids that already exist; duplicates are skipped.
func patchedDidDoc(doc map[string]any, extras []string) {
	didID, _ := doc["id"].(string)
	if didID == "" {
		return
	}
	methods, _ := doc["verificationMethod"].([]any)
	if len(methods) == 0 {
		return
	}
	template, _ := methods[0].(map[string]any)
	if template == nil {
		return
	}
	// Collect existing kid fragments so we don't duplicate.
	existing := map[string]struct{}{}
	for _, m := range methods {
		mm, _ := m.(map[string]any)
		if id, _ := mm["id"].(string); id != "" {
			if i := strings.IndexByte(id, '#'); i >= 0 {
				existing[id[i+1:]] = struct{}{}
			}
		}
	}
	for _, kid := range extras {
		if kid == "" {
			continue
		}
		if _, ok := existing[kid]; ok {
			continue
		}
		clone := map[string]any{}
		for k, v := range template {
			clone[k] = v
		}
		clone["id"] = didID + "#" + kid
		methods = append(methods, clone)
		existing[kid] = struct{}{}
	}
	doc["verificationMethod"] = methods

	// Normalise assertionMethod / authentication to reference the FULL
	// verification-method ids (did#kid). Inji Certify's upstream did.json lists
	// the BARE did (no #fragment) in these relationships, which a strict
	// verifier (the @digitalbazaar suites walt.id-style wallets use) won't
	// accept as authorising a proof whose verificationMethod is did#kid — so
	// the proof check fails even though the key is present. Point both at every
	// VM id instead. This issuer uses one key for both relationships.
	vmIDs := make([]any, 0, len(methods))
	for _, m := range methods {
		if mm, _ := m.(map[string]any); mm != nil {
			if id, _ := mm["id"].(string); id != "" {
				vmIDs = append(vmIDs, id)
			}
		}
	}
	if len(vmIDs) > 0 {
		doc["assertionMethod"] = vmIDs
		doc["authentication"] = vmIDs
	}
}

// Seed each observer from its own env-var. Primary gets INJI_PROXY_EXTRA_KIDS
// (unchanged for backward compat); pre-auth gets a separate
// INJI_PROXY_PREAUTH_EXTRA_KIDS so operators can pre-populate the two
// observers independently. Either list is comma-separated kid fragments.
func init() {
	seed := func(env string, obs *injidid.Observer) {
		v := os.Getenv(env)
		if v == "" {
			return
		}
		for _, k := range strings.Split(v, ",") {
			obs.Add(k)
		}
	}
	seed("INJI_PROXY_EXTRA_KIDS", injidid.Primary)
	seed("INJI_PROXY_PREAUTH_EXTRA_KIDS", injidid.Preauth)
}

// injectCredentialContext adds credential_definition.@context when a wallet
// omits it. Inji Certify's LdpVcCredentialRequestValidator rejects
// w3c_vcdm_2 requests without it; Mimoto sends one, walt.id doesn't.
func injectCredentialContext(body []byte) ([]byte, bool) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, false
	}
	cd, ok := parsed["credential_definition"].(map[string]any)
	if !ok {
		return body, false
	}
	if _, hasCtx := cd["@context"]; hasCtx {
		return body, false
	}
	cd["@context"] = []string{"https://www.w3.org/ns/credentials/v2"}
	parsed["credential_definition"] = cd
	patched, err := json.Marshal(parsed)
	if err != nil {
		return body, false
	}
	return patched, true
}

// truncateForLog trims log strings so a misbehaving upstream can't flood
// the log with multi-megabyte error bodies.
func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%s…(%d more)", s[:n], len(s)-n)
}
