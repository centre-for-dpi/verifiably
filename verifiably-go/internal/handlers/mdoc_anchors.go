package handlers

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── GET /trust/mdoc-anchors — the mdoc IACA trust anchor(s) of THIS deployment ──
//
// WHY THIS ENDPOINT EXISTS
// Every deploy.sh run on a fresh host generates a new IACA root
// (scripts/gen-caddy.sh provision_issuer2_certificates -> cmd/mdl-pki-gen).
// A wallet that ships the anchor compiled into its source therefore stops
// trusting this deployment's mdocs the moment the certificate is regenerated,
// and the failure surfaces only as "No trusted certificate was found while
// validating the X.509 chain" — pointing at the certificate, not at the stale
// constant that actually caused it. This endpoint lets the wallet learn the
// current anchor over HTTPS at credential-acceptance time instead.
//
// THIS IS A PROOF OF CONCEPT — the server certifies its own trust anchor.
// A caller that trusts this response trusts the issuer's claim about itself,
// so a compromised issuer can mint an anchor and self-certify. That is
// acceptable only because this deployment has exactly one mdoc issuer and the
// generated PKI says so in its own DN (O=POC-DO-NOT-TRUST).
//
// PRODUCTION REPLACEMENT: the Hub's VICAL list.
// ISO/IEC 18013-5's VICAL model is a list of legitimate issuers signed by an
// authority DISTINCT from any single issuer, so a compromised issuer cannot
// self-certify — the wallet checks the anchor against a signature that the
// issuer does not hold the key for. That belongs to the Hub, which already has
// the shape for it: internal/trust/registry.go's TrustedIssuer model (DID-keyed
// today, no X.509 field yet) and internal/handlers/trust.go's GET
// /trust-registry (a JWT of trusted issuers signed by the Hub, not by the
// issuer being vouched for). Adding an x5c/IACA field to TrustedIssuer and
// serving it from the Hub's already-signed list is the migration path; this
// endpoint is the interim single-issuer stand-in and should be deleted then.
//
// ── SECURITY DECISION: public, unauthenticated, and deliberately NOT signed ──
// Resolved here rather than deferred, because a future reader will ask.
//
// Public and unauthenticated is required, not merely convenient: a wallet in
// the field needs the anchor BEFORE it has accepted any credential from this
// deployment — the anchor is what lets it accept the first one. Gating this
// behind a credential from the same deployment is circular.
//
// Not signed, unlike /trust-registry, and the asymmetry is intentional:
//
//   - /trust-registry is signed (ES256, verifiable via /.well-known/jwks.json)
//     because it is designed to be relayed — a verifier may obtain the list
//     from a cache, a mirror or a peer node, so authenticity has to survive
//     leaving the TLS connection that served it.
//
//   - /trust/mdoc-anchors is fetched by the wallet directly from the exact
//     origin it just resolved the credential offer from (the OID4VCI
//     credential_issuer URL), over TLS, in the same online exchange in which it
//     is about to accept a credential from that same origin. Signing the
//     response with a key from that same origin adds no security: an attacker
//     who can forge the anchor response can forge the signature over it too,
//     because both authorities are the issuer itself. The signature would be
//     self-referential — proof that the issuer said it, which TLS to that origin
//     already establishes.
//
// So TLS + same-origin-as-the-offer is the trust boundary for the POC, and the
// honest statement is that this endpoint's ceiling is "the issuer's own claim".
// Raising that ceiling is exactly what the VICAL/Hub path above is for; it is a
// change of signing AUTHORITY, not the addition of a signature.
//
// SCOPE LIMIT: serves only the IACA root(s) — never dsc.pem (the Document
// Signer, whose private key signs credentials) and never issuer2.env (which
// holds the DSC private key coordinates). Both live in the same directory. The
// allowlist below is what keeps a directory read from becoming a key leak.

// mdocAnchorFilenames is the allowlist of files served as trust anchors.
// An allowlist, not a *.pem glob: dsc.pem sits in the same directory and is the
// Document Signer, not an anchor — serving it would invite a wallet to trust a
// leaf as a root. issuer2.env in that directory holds the DSC PRIVATE key, so a
// pattern match over the directory is a key-disclosure bug waiting to happen.
var mdocAnchorFilenames = []string{"iaca.pem"}

// mdocAnchorTTL bounds how long a parsed anchor set is reused before the file is
// re-read. Short by design: a redeploy that regenerates the IACA must become
// visible without restarting verifiably-go, which is the entire failure this
// endpoint exists to fix — caching it for the process lifetime would just move
// the staleness from the wallet binary into the server process.
const mdocAnchorTTL = 30 * time.Second

// mdocAnchorCache memoizes the on-disk anchors for mdocAnchorTTL.
// Absence is cached too (as an empty slice), so a deployment without issuer2
// does not stat a missing file on every request.
type mdocAnchorCache struct {
	mu       sync.Mutex
	pems     []string
	loadedAt time.Time
	// now is injected by tests to exercise TTL expiry without sleeping.
	now func() time.Time
}

var anchorCache = &mdocAnchorCache{}

func (c *mdocAnchorCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// load returns the current anchors, re-reading from disk when the TTL has
// elapsed. Errors are NOT cached — a transient read failure must not pin a 503
// for the whole TTL window.
func (c *mdocAnchorCache) load(dir string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.loadedAt.IsZero() && c.clock().Sub(c.loadedAt) < mdocAnchorTTL {
		return c.pems, nil
	}
	pems, err := readMdocAnchors(dir)
	if err != nil {
		return nil, err
	}
	c.pems = pems
	c.loadedAt = c.clock()
	return pems, nil
}

// reset drops the cached value. Test seam; also correct to call after a deploy.
func (c *mdocAnchorCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pems = nil
	c.loadedAt = time.Time{}
}

// readMdocAnchors reads the allowlisted anchor files from dir and returns them
// as normalized PEM strings.
//
// A missing file is not an error — it yields an empty slice, which the handler
// turns into a documented 404. That distinction matters: "issuer2 was never
// configured for this deployment" is a normal state, while "the file is present
// but unreadable or not a certificate" is a real fault the operator must see.
//
// Each file is parsed (pem.Decode + x509.ParseCertificate) rather than shipped
// as raw bytes. A half-written file during a redeploy would otherwise be served
// as a valid-looking 200 that every wallet then fails to parse, turning a
// transient race into an inscrutable client-side error.
func readMdocAnchors(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	var out []string
	for _, name := range mdocAnchorFilenames {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		certs, err := parseCertificatePEMs(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, certs...)
	}
	sort.Strings(out)
	return out, nil
}

// parseCertificatePEMs decodes every CERTIFICATE block in raw, verifies each one
// really is an X.509 certificate, and re-encodes it canonically. Re-encoding (as
// opposed to echoing the file) strips any trailing junk, comments or CRLFs the
// generator or an operator's editor may have left, so the wallet receives
// exactly what it can parse.
func parseCertificatePEMs(raw []byte) ([]string, error) {
	var out []string
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, err
		}
		out = append(out, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: block.Bytes,
		}))))
	}
	return out, nil
}

// MdocAnchorsResponse is the GET /trust/mdoc-anchors body.
//
// JSON array of PEM strings rather than a raw PEM bundle (application/x-pem-file).
// The consumer is the wallet's X509Module
// getTrustedCertificatesForVerification callback, whose contract is already
// `string[]` of PEM certificates — so a JSON array maps to it with a single
// res.json(), while a concatenated bundle would force the wallet to hand-split
// on "-----END CERTIFICATE-----" boundaries in JS to produce that same array.
// The wrapper object (rather than a bare top-level array) leaves room to add
// fields — a VICAL signature, an expiry, an issuer identifier — without
// breaking a client that already parses this shape.
type MdocAnchorsResponse struct {
	// Anchors holds one PEM-encoded IACA certificate per element.
	Anchors []string `json:"anchors"`
	// UpdatedAt is the mtime of the newest anchor file, RFC3339. Advisory only:
	// it lets an operator confirm from curl that a redeploy actually rotated the
	// certificate, without decoding the PEM.
	UpdatedAt string `json:"updated_at,omitempty"`
	// Poc is always true and is part of the contract, not decoration: a client
	// that later learns to consume a Hub-signed VICAL can branch on it, and an
	// operator reading a raw response sees the caveat without finding this file.
	Poc bool `json:"poc"`
}

// ServeMdocAnchors handles GET /trust/mdoc-anchors.
//
// Returns the IACA root certificate(s) this deployment currently signs mdocs
// under, as JSON {"anchors": ["-----BEGIN CERTIFICATE-----..."], "poc": true}.
// Public and unauthenticated; see the package-level rationale above for why
// that is required rather than merely convenient, and why — unlike
// /trust-registry — the payload is deliberately not signed.
//
// Reads the file per request behind a 30 s TTL cache, so an operator's redeploy
// is picked up without restarting verifiably-go.
//
// Status codes:
//
//	200 — one or more anchors on disk.
//	404 — no anchor file present: issuer2 is not configured for this deployment,
//	      or certificates have not been generated yet. NOT an empty 200, which a
//	      wallet would cache as "this issuer has no anchors" and then reject
//	      every credential with a confusing trust error instead of a clear one.
//	503 — the anchor path is not configured at all (VERIFIABLY_MDOC_CERTS_DIR
//	      unset), matching how the other handlers here report unconfigured
//	      subsystems.
//	500 — the file exists but is unreadable or is not a valid certificate.
//
// PRODUCTION REPLACEMENT: the Hub's VICAL list, signed by an authority distinct
// from any single issuer, so a compromised issuer cannot self-certify. See the
// package-level comment above for the concrete migration path through
// internal/trust/registry.go's TrustedIssuer and the Hub's /trust-registry.
func (h *H) ServeMdocAnchors(w http.ResponseWriter, r *http.Request) {
	// CORS, matching ServeIssuerMetadata: the payload is public by design (see
	// above), and a browser-based wallet fetches it cross-origin from whatever
	// page resolved the offer. Same posture as the other public discovery
	// endpoints in this package.
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.MdocCertsDir == "" {
		http.Error(w, "mdoc trust anchors not configured", http.StatusServiceUnavailable)
		return
	}

	pems, err := anchorCache.load(h.MdocCertsDir)
	if err != nil {
		slog.Error("mdoc anchors: read", "dir", h.MdocCertsDir, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(pems) == 0 {
		slog.Warn("mdoc anchors: no certificate on disk", "dir", h.MdocCertsDir)
		http.Error(w, "no mdoc trust anchor available", http.StatusNotFound)
		return
	}

	resp := MdocAnchorsResponse{Anchors: pems, Poc: true}
	if ts, ok := newestAnchorMtime(h.MdocCertsDir); ok {
		resp.UpdatedAt = ts.UTC().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	// Short max-age for the same reason mdocAnchorTTL is short: a redeploy
	// rotates this value, and an intermediary caching it for an hour would
	// reintroduce exactly the staleness this endpoint removes.
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(resp)
}

// newestAnchorMtime returns the most recent mtime across the allowlisted anchor
// files. Best-effort: a stat failure just omits UpdatedAt from the response.
func newestAnchorMtime(dir string) (time.Time, bool) {
	var newest time.Time
	var found bool
	for _, name := range mdocAnchorFilenames {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if !found || fi.ModTime().After(newest) {
			newest = fi.ModTime()
			found = true
		}
	}
	return newest, found
}
