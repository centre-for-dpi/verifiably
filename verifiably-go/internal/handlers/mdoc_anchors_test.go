package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestIACA generates a self-signed CA certificate shaped like the one
// cmd/mdl-pki-gen emits (P-256, CA:TRUE, C/ST present), so these tests exercise
// a real certificate rather than an arbitrary blob.
func newTestIACA(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"POC-DO-NOT-TRUST"},
			Country:      []string{"DO"},
			Province:     []string{"DO-01"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeIACA writes an iaca.pem into dir and returns its PEM bytes.
func writeIACA(t *testing.T, dir, cn string) []byte {
	t.Helper()
	pemBytes := newTestIACA(t, cn)
	if err := os.WriteFile(filepath.Join(dir, "iaca.pem"), pemBytes, 0o600); err != nil {
		t.Fatalf("write iaca.pem: %v", err)
	}
	return pemBytes
}

func doAnchorsRequest(t *testing.T, h *H) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeMdocAnchors(rec, httptest.NewRequest(http.MethodGet, "/trust/mdoc-anchors", nil))
	return rec
}

func decodeAnchors(t *testing.T, rec *httptest.ResponseRecorder) MdocAnchorsResponse {
	t.Helper()
	var got MdocAnchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, rec.Body.String())
	}
	return got
}

// TestServeMdocAnchors_ReturnsGeneratedCert is the happy path: a real generated
// certificate on disk comes back verbatim and parseable.
func TestServeMdocAnchors_ReturnsGeneratedCert(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	dir := t.TempDir()
	want := writeIACA(t, dir, "TEST POC IACA")

	h := &H{MdocCertsDir: dir}
	rec := doAnchorsRequest(t, h)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("Cache-Control not set")
	}

	got := decodeAnchors(t, rec)
	if !got.Poc {
		t.Error("poc = false, want true — the response must self-identify as POC material")
	}
	if len(got.Anchors) != 1 {
		t.Fatalf("len(anchors) = %d, want 1", len(got.Anchors))
	}

	// The served PEM must parse back into the same certificate that is on disk.
	block, _ := pem.Decode([]byte(got.Anchors[0]))
	if block == nil {
		t.Fatal("served anchor is not valid PEM")
	}
	served, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("served anchor does not parse as a certificate: %v", err)
	}
	wantBlock, _ := pem.Decode(want)
	onDisk, err := x509.ParseCertificate(wantBlock.Bytes)
	if err != nil {
		t.Fatalf("parse on-disk certificate: %v", err)
	}
	if !served.Equal(onDisk) {
		t.Errorf("served certificate differs from the one on disk (served CN=%q, disk CN=%q)",
			served.Subject.CommonName, onDisk.Subject.CommonName)
	}
	if !served.IsCA {
		t.Error("served anchor is not a CA certificate")
	}
}

// writeInjiRoot writes a root cert under one of Inji Certify's allowlisted
// filenames (see mdocAnchorFilenames's doc comment) into dir.
func writeInjiRoot(t *testing.T, dir, filename, cn string) []byte {
	t.Helper()
	pemBytes := newTestIACA(t, cn)
	if err := os.WriteFile(filepath.Join(dir, filename), pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
	return pemBytes
}

// TestServeMdocAnchors_IncludesInjiRoots pins the fix for a real bug found
// during Task 6 end-to-end verification: a real mDL, fully issued and
// correctly signed by Inji Certify, still failed wallet-side trust
// verification because this endpoint served only walt.id's iaca.pem — Inji
// Certify signs with its OWN independent self-signed root, generated inside
// its local mock-HSM keystore, which this endpoint never saw at all. Both
// Inji roots (auth-code and pre-auth — two independent instances, two
// independent keystores) must be included alongside iaca.pem whenever
// deploy.sh's provision_inji_root_anchors has extracted them.
func TestServeMdocAnchors_IncludesInjiRoots(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	dir := t.TempDir()
	writeIACA(t, dir, "TEST WALT.ID IACA")
	writeInjiRoot(t, dir, "inji-authcode-root.pem", "TEST INJI AUTHCODE ROOT")
	writeInjiRoot(t, dir, "inji-preauth-root.pem", "TEST INJI PREAUTH ROOT")

	h := &H{MdocCertsDir: dir}
	rec := doAnchorsRequest(t, h)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	got := decodeAnchors(t, rec)
	if len(got.Anchors) != 3 {
		t.Fatalf("len(anchors) = %d, want 3 (iaca.pem + both Inji roots), got: %v", len(got.Anchors), got.Anchors)
	}

	wantCNs := map[string]bool{
		"TEST WALT.ID IACA":       false,
		"TEST INJI AUTHCODE ROOT": false,
		"TEST INJI PREAUTH ROOT":  false,
	}
	for _, anchor := range got.Anchors {
		block, _ := pem.Decode([]byte(anchor))
		if block == nil {
			t.Fatalf("served anchor is not valid PEM: %q", anchor)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("served anchor does not parse: %v", err)
		}
		if _, ok := wantCNs[cert.Subject.CommonName]; !ok {
			t.Errorf("unexpected anchor CN %q in response", cert.Subject.CommonName)
			continue
		}
		wantCNs[cert.Subject.CommonName] = true
	}
	for cn, seen := range wantCNs {
		if !seen {
			t.Errorf("expected anchor CN %q was not present in the response", cn)
		}
	}
}

// TestServeMdocAnchors_OnlyInjiRootPresent covers a deployment where only
// the pre-auth Inji instance is running (e.g. `deploy.sh up inji` without
// the auth-code scenario ever having generated its own root, or a fresh
// deploy where provision_inji_root_anchors has only reached one instance
// so far) — walt.id's iaca.pem absent entirely, not just empty.
func TestServeMdocAnchors_OnlyInjiRootPresent(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	dir := t.TempDir()
	writeInjiRoot(t, dir, "inji-preauth-root.pem", "TEST INJI PREAUTH ROOT")

	h := &H{MdocCertsDir: dir}
	rec := doAnchorsRequest(t, h)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	got := decodeAnchors(t, rec)
	if len(got.Anchors) != 1 {
		t.Fatalf("len(anchors) = %d, want 1 (only the pre-auth root)", len(got.Anchors))
	}
}

// TestServeMdocAnchors_MissingFile covers the documented 404: issuer2 configured
// but no certificate generated yet. Must not panic and must not be an empty 200,
// which a wallet would cache as "this issuer has no anchors".
func TestServeMdocAnchors_MissingFile(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	h := &H{MdocCertsDir: t.TempDir()} // exists, but empty
	rec := doAnchorsRequest(t, h)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%q)", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		t.Error("404 body is empty; want a diagnosable message")
	}
}

// TestServeMdocAnchors_NonexistentDir covers issuer2 not configured for this
// deployment at all — a missing directory, not merely a missing file.
func TestServeMdocAnchors_NonexistentDir(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	h := &H{MdocCertsDir: filepath.Join(t.TempDir(), "does-not-exist")}
	rec := doAnchorsRequest(t, h)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%q)", rec.Code, rec.Body.String())
	}
}

// TestServeMdocAnchors_Unconfigured covers MdocCertsDir empty — the endpoint is
// routed but the deployment never told it where the certs live.
func TestServeMdocAnchors_Unconfigured(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	rec := doAnchorsRequest(t, &H{MdocCertsDir: ""})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%q)", rec.Code, rec.Body.String())
	}
}

// TestServeMdocAnchors_CorruptFile proves a malformed file is a 500, not a 200
// carrying garbage a wallet would fail to parse with an inscrutable error.
func TestServeMdocAnchors_CorruptFile(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	dir := t.TempDir()
	// Well-formed PEM envelope, contents that are not a certificate — the case a
	// raw file-echo implementation would happily serve.
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	if err := os.WriteFile(filepath.Join(dir, "iaca.pem"), bad, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	rec := doAnchorsRequest(t, &H{MdocCertsDir: dir})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%q)", rec.Code, rec.Body.String())
	}
}

// TestServeMdocAnchors_RegeneratedCertIsPickedUp is the regression this whole
// endpoint exists to prevent, one level down: a redeploy rewrites iaca.pem, and
// the endpoint must serve the NEW root once the TTL lapses — without a restart.
// A process-lifetime cache would just move the staleness from the wallet binary
// into the server.
func TestServeMdocAnchors_RegeneratedCertIsPickedUp(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	// Virtual clock so the TTL is exercised without sleeping.
	now := time.Now()
	anchorCache.now = func() time.Time { return now }
	t.Cleanup(func() { anchorCache.now = nil })

	dir := t.TempDir()
	writeIACA(t, dir, "FIRST DEPLOY IACA")
	h := &H{MdocCertsDir: dir}

	first := decodeAnchors(t, doAnchorsRequest(t, h))
	if len(first.Anchors) != 1 {
		t.Fatalf("len(anchors) = %d, want 1", len(first.Anchors))
	}

	// Redeploy regenerates the root.
	writeIACA(t, dir, "SECOND DEPLOY IACA")

	// Within the TTL the cached value is still served — this is the intended
	// behaviour, asserted so the TTL is not silently zero.
	cached := decodeAnchors(t, doAnchorsRequest(t, h))
	if cached.Anchors[0] != first.Anchors[0] {
		t.Error("anchor changed inside the TTL window; the cache is not being used")
	}

	// Past the TTL the new root must appear.
	now = now.Add(mdocAnchorTTL + time.Second)
	refreshed := decodeAnchors(t, doAnchorsRequest(t, h))
	if len(refreshed.Anchors) != 1 {
		t.Fatalf("len(anchors) = %d, want 1", len(refreshed.Anchors))
	}
	if refreshed.Anchors[0] == first.Anchors[0] {
		t.Fatal("still serving the pre-redeploy anchor after the TTL lapsed — " +
			"a regenerated certificate would be invisible without a restart")
	}

	block, _ := pem.Decode([]byte(refreshed.Anchors[0]))
	if block == nil {
		t.Fatal("refreshed anchor is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("refreshed anchor does not parse: %v", err)
	}
	if cert.Subject.CommonName != "SECOND DEPLOY IACA" {
		t.Errorf("CommonName = %q, want SECOND DEPLOY IACA", cert.Subject.CommonName)
	}
}

// TestReadMdocAnchors_IgnoresNonAnchorFiles is the key-disclosure guard: dsc.pem
// (the Document Signer leaf) and issuer2.env (which holds the DSC PRIVATE key)
// share the directory with iaca.pem. A glob-based implementation would serve
// them; the allowlist must not.
func TestReadMdocAnchors_IgnoresNonAnchorFiles(t *testing.T) {
	dir := t.TempDir()
	wantPEM := writeIACA(t, dir, "ONLY THE ROOT")

	if err := os.WriteFile(filepath.Join(dir, "dsc.pem"), newTestIACA(t, "DOCUMENT SIGNER"), 0o600); err != nil {
		t.Fatalf("write dsc.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "issuer2.env"),
		[]byte("VERIFIABLY_ISSUER2_KEY_D=super-secret-private-scalar\n"), 0o600); err != nil {
		t.Fatalf("write issuer2.env: %v", err)
	}

	got, err := readMdocAnchors(dir)
	if err != nil {
		t.Fatalf("readMdocAnchors: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 — only iaca.pem may be served", len(got))
	}

	block, _ := pem.Decode([]byte(got[0]))
	served, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse served: %v", err)
	}
	if served.Subject.CommonName != "ONLY THE ROOT" {
		t.Errorf("served CN = %q, want ONLY THE ROOT", served.Subject.CommonName)
	}
	wantBlock, _ := pem.Decode(wantPEM)
	if wantCert, _ := x509.ParseCertificate(wantBlock.Bytes); !served.Equal(wantCert) {
		t.Error("served certificate is not the IACA on disk")
	}
	for _, p := range got {
		if len(p) > 0 && p[0] != '-' {
			t.Errorf("served value is not PEM: %q", p)
		}
	}
}

// TestServeMdocAnchors_OptionsPreflight covers the CORS preflight the route
// registers, so a browser-based wallet is not blocked before the GET.
func TestServeMdocAnchors_OptionsPreflight(t *testing.T) {
	anchorCache.reset()
	t.Cleanup(anchorCache.reset)

	rec := httptest.NewRecorder()
	// Deliberately unconfigured: a preflight must succeed before any state check.
	(&H{}).ServeMdocAnchors(rec, httptest.NewRequest(http.MethodOptions, "/trust/mdoc-anchors", nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}
