// inji-preauth-proxy — transparent reverse proxy in front of an Inji Certify
// pre-auth instance. Listens at Inji's network identity so strict OID4VCI
// wallets (walt.id, Sphereon, etc.) can claim pre-auth credentials despite
// Inji's non-conformant metadata URL layout.
//
// Two classes of interception:
//
//   1. GET /.well-known/openid-credential-issuer
//      Inji advertises `credential_issuer: http://inji-certify-preauth:8090`
//      but serves metadata under /v1/certify/issuance/.well-known/... not at
//      the root. Strict wallets follow the issuer identifier verbatim and
//      404 at the root. This handler answers at the root, proxies to
//      upstream's real metadata URL, and rewrites the payload so walt.id's
//      strict JSON parser accepts it:
//        * null-valued optional fields stripped (JsonNull breaks
//          JsonDataObjectSerializer.transformDeserialize)
//        * every `display` object stripped (non-essential; walt.id's
//          DisplayProperties serializer chokes on some Inji display shapes)
//        * a bridge-local token_endpoint injected when Inji omits it
//
//   2. POST /v1/certify/issuance/credential
//      Inji's VCIssuanceUtil.isValidLdpVCRequest runs strict set-equality on
//      credential_definition.@context + type. Walt.id (1) omits @context
//      entirely from the request body, (2) derives type from issuer
//      metadata. We look up the advertised @context + type for the picked
//      config id from upstream and rewrite the outgoing body to match.
//
// Every other path is a transparent httputil.ReverseProxy to the backend.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	upstreamURL    string
	listenAddr     string
	transparent    *httputil.ReverseProxy
	metadataClient = &http.Client{Timeout: 30 * time.Second}
)

const injiMetadataPath = "/v1/certify/issuance/.well-known/openid-credential-issuer"

func main() {
	upstreamURL = env("UPSTREAM_URL", "http://inji-certify-preauth-backend:8090")
	listenAddr = env("LISTEN_ADDR", ":8090")

	u, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("bad UPSTREAM_URL: %v", err)
	}
	transparent = httputil.NewSingleHostReverseProxy(u)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", serveIssuerMetadata)
	mux.HandleFunc("GET /v1/certify/issuance/.well-known/openid-credential-issuer", serveIssuerMetadata)
	mux.HandleFunc("POST /v1/certify/issuance/credential", serveCredentialRequest)
	mux.Handle("/", transparent)

	log.Printf("inji-preauth-proxy: listening on %s, upstream=%s", listenAddr, upstreamURL)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// serveIssuerMetadata proxies to upstream's real metadata URL and rewrites
// the payload so strict OID4VCI wallets can parse it.
func serveIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	body, status, err := fetchUpstream(upstreamURL + injiMetadataPath)
	if err != nil {
		log.Printf("metadata upstream error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if status != http.StatusOK {
		log.Printf("metadata upstream non-200: %d body=%s", status, truncate(string(body), 200))
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	rewritten, err := rewriteMetadata(body)
	if err != nil {
		log.Printf("metadata rewrite failed: %v — passing through", err)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rewritten)
}

// serveCredentialRequest rewrites credential_definition.@context + type to
// exactly match what upstream advertises for the picked config, then
// forwards the request to upstream's credential endpoint. Bypasses the
// rewrite when the request isn't ldp_vc (SD-JWT matcher doesn't need this).
func serveCredentialRequest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Sanitise walt.id's quirks in the credential REQUEST before forwarding:
	//   - a top-level `display` block (echoed from the offered config) →
	//     Inji's CredentialRequest DTO isn't ignoreUnknown, so it 500s with
	//     "Unrecognized field display".
	//   - an empty `credential_definition: {}` on a vc+sd-jwt request → Inji
	//     rejects it as an invalid_credential_request (SD-JWT keys off `vct`).
	// Neither belongs in the request; alignCredentialDefinition below still
	// rewrites a populated credential_definition for ldp_vc.
	body = sanitizeCredentialRequest(body)
	if patched, ok := alignCredentialDefinition(body); ok {
		body = patched
	}
	// Forward to upstream with the (possibly-patched) body and copied headers.
	req, err := http.NewRequestWithContext(r.Context(), r.Method,
		upstreamURL+"/v1/certify/issuance/credential", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, h := range []string{"Authorization", "Content-Type", "Accept", "DPoP"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("credential upstream error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("credential REQ authHdrLen=%d body=%s",
		len(r.Header.Get("Authorization")), truncate(string(body), 1500))
	if resp.StatusCode >= 400 {
		log.Printf("credential upstream %d body=%s", resp.StatusCode, truncate(string(respBody), 400))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func fetchUpstream(url string) ([]byte, int, error) {
	resp, err := metadataClient.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func rewriteMetadata(body []byte) ([]byte, error) {
	var meta map[string]any
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	meta = stripNulls(meta).(map[string]any)
	stripDisplay(meta)
	// Force walt.id's wallet onto its key-proof branch
	// (IssuanceServiceBase.isKeyProofRequiredForOfferedCredential at
	// waltid-wallet-api/.../IssuanceServiceBase.kt:154-159). That branch
	// hits ProofOfPossessionFactory.keyProofOfPossession which passes no
	// OpenIDClientConfig, so JWTProofBuilder leaves clientId = null and
	// OMITS the `iss` claim entirely — which is what the OID4VCI spec
	// actually requires for anonymous pre-auth flows. The DID branch
	// (didProofOfPossession) hard-codes clientID = holder's DID and
	// unconditionally writes iss, tripping Inji's JwtProofValidator iss ==
	// access_token.client_id check. The switch fires when
	// cryptographic_binding_methods_supported contains jwk|cose_key AND
	// does NOT contain "did". Strip "did:*" members from every config.
	stripDidBindingMethods(meta)
	// Inji's metadata omits a top-level token_endpoint for pre-auth.
	// Walt.id's wallet derives it from authorization_servers[0] +
	// /.well-known/oauth-authorization-server — which Inji 404s on.
	// Inline a token_endpoint the wallet can POST to directly; this path is
	// served by upstream at /v1/certify/oauth/token.
	if _, ok := meta["token_endpoint"]; !ok {
		// Inji v0.14.0 serves the pre-auth token endpoint at
		// /v1/certify/oauth/token (NOT under /v1/certify/issuance/).
		// Advertise the same path on our identity so the wallet's POST
		// hits us at that path and the transparent reverse proxy forwards
		// it verbatim to upstream.
		issuer, _ := meta["credential_issuer"].(string)
		meta["token_endpoint"] = strings.TrimRight(issuer, "/") + "/v1/certify/oauth/token"
	}
	return json.Marshal(meta)
}

// alignCredentialDefinition rewrites the outgoing request's
// credential_definition.@context + .type so they set-equal what upstream
// advertises for the picked config. See the file-header comment for why
// this is needed.
func alignCredentialDefinition(body []byte) ([]byte, bool) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, false
	}
	if parsed["format"] != "ldp_vc" {
		return body, false
	}
	cd, _ := parsed["credential_definition"].(map[string]any)
	if cd == nil {
		cd = map[string]any{}
		parsed["credential_definition"] = cd
	}
	reqType, _ := cd["type"].([]any)

	metaBody, status, err := fetchUpstream(upstreamURL + injiMetadataPath)
	if err != nil || status != http.StatusOK {
		return body, false
	}
	var meta map[string]any
	if err := json.Unmarshal(metaBody, &meta); err != nil {
		return body, false
	}
	configs, _ := meta["credential_configurations_supported"].(map[string]any)
	if configs == nil {
		return body, false
	}
	advCtx, advType, ok := pickConfig(configs, reqType)
	if !ok {
		return body, false
	}
	cd["@context"] = advCtx
	cd["type"] = advType
	out, err := json.Marshal(parsed)
	if err != nil {
		return body, false
	}
	return out, true
}

func pickConfig(configs map[string]any, reqType []any) ([]any, []any, bool) {
	reqSet := toStringSet(reqType)
	var firstLdp map[string]any
	for _, raw := range configs {
		cfg, _ := raw.(map[string]any)
		if cfg == nil || cfg["format"] != "ldp_vc" {
			continue
		}
		if firstLdp == nil {
			firstLdp = cfg
		}
		cd, _ := cfg["credential_definition"].(map[string]any)
		if cd == nil {
			continue
		}
		advType, _ := cd["type"].([]any)
		if setsEqual(reqSet, toStringSet(advType)) {
			return cd["@context"].([]any), advType, true
		}
	}
	if firstLdp != nil {
		if cd, ok := firstLdp["credential_definition"].(map[string]any); ok {
			ctx, _ := cd["@context"].([]any)
			typ, _ := cd["type"].([]any)
			if ctx != nil && typ != nil {
				return ctx, typ, true
			}
		}
	}
	return nil, nil, false
}

func toStringSet(in []any) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out[s] = struct{}{}
		}
	}
	return out
}

func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func stripNulls(v any) any {
	switch vv := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(vv))
		for k, val := range vv {
			if val == nil {
				continue
			}
			out[k] = stripNulls(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(vv))
		for _, item := range vv {
			if item == nil {
				continue
			}
			out = append(out, stripNulls(item))
		}
		return out
	default:
		return v
	}
}

// stripDidBindingMethods removes every "did:*" entry from
// credential_configurations_supported[*].cryptographic_binding_methods_supported
// and, when the resulting list is empty or missing a jwk entry, appends "jwk".
// Purpose: trigger walt.id's isKeyProofRequiredForOfferedCredential to return
// true for every advertised config so its wallet takes the key-proof code
// path (no iss claim on the resulting proof JWT).
func stripDidBindingMethods(meta map[string]any) {
	configs, _ := meta["credential_configurations_supported"].(map[string]any)
	if configs == nil {
		return
	}
	for _, raw := range configs {
		cfg, _ := raw.(map[string]any)
		if cfg == nil {
			continue
		}
		methods, _ := cfg["cryptographic_binding_methods_supported"].([]any)
		if methods == nil {
			cfg["cryptographic_binding_methods_supported"] = []any{"jwk"}
			continue
		}
		kept := make([]any, 0, len(methods))
		hasJwk := false
		for _, m := range methods {
			s, _ := m.(string)
			if strings.HasPrefix(s, "did") {
				continue
			}
			if s == "jwk" {
				hasJwk = true
			}
			kept = append(kept, m)
		}
		if !hasJwk {
			kept = append(kept, "jwk")
		}
		cfg["cryptographic_binding_methods_supported"] = kept
	}
}

// sanitizeCredentialRequest removes fields walt.id adds to a credential request
// that Inji Certify rejects: a top-level `display` block (Inji's
// CredentialRequest DTO isn't ignoreUnknown → 500 "Unrecognized field display")
// and an EMPTY `credential_definition: {}` (Inji 400s a vc+sd-jwt request that
// carries one — SD-JWT keys off `vct`). A populated credential_definition is
// left intact for alignCredentialDefinition to rewrite. Returns the body
// unchanged when it isn't a JSON object or has nothing to strip.
func sanitizeCredentialRequest(body []byte) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}
	changed := false
	if _, ok := parsed["display"]; ok {
		delete(parsed, "display")
		changed = true
	}
	if cd, ok := parsed["credential_definition"].(map[string]any); ok && len(cd) == 0 {
		delete(parsed, "credential_definition")
		changed = true
	}
	if !changed {
		return body
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return out
}

func stripDisplay(v any) {
	switch vv := v.(type) {
	case map[string]any:
		delete(vv, "display")
		for _, child := range vv {
			stripDisplay(child)
		}
	case []any:
		for _, item := range vv {
			stripDisplay(item)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
