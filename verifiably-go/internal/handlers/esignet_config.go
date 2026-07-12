package handlers

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- eSignet auth-method (login-factor / ACR) config ------------------------
//
// eSignet decides which login factors (PIN / OTP / Wallet / …) to present from
// the `acr_values` on the /authorize request, constrained by the OIDC client's
// registered authContextRefs. verifiably owns both levers for the in-app Inji
// auth-code flow: StartInjiClaim REQUESTS acr_values, and this surface manages
// the client's registered set. The admin's pick is stored in eSignet's own
// client registration (client_detail.acr_values) as the single source of truth
// and also drives what verifiably requests — so a change is visible at the next
// login with no restart.
//
// eSignet exposes no client-mgmt GET API, so current values are READ from the
// eSignet Postgres directly; the WRITE is a targeted single-column UPDATE plus a
// Redis cache flush (eSignet caches client_detail and does not invalidate on
// external writes) — the same cache-coherent, no-restart pattern deploy.sh's
// repair_injiweb_client_redirect_uri() uses. All of it runs over the mounted
// docker socket (create-exec + start), the same transport dockerRestart() uses,
// so it needs no network route to the eSignet containers.

// esignetFactor is one entry of eSignet's amr_acr_mapping.json: an ACR value,
// its human label, the eSignet amr code, and a one-line description.
type esignetFactor struct {
	ACR  string
	Name string
	AMR  string
	Desc string
}

// esignetAllFactors is the full acr↔factor set eSignet ships (amr_acr_mapping
// .json), in display order. PIN/OTP/Wallet are the ones the mock-identity
// deployment actually backs; the rest need extra plugins (see esignetBackedACRs).
var esignetAllFactors = []esignetFactor{
	{"mosip:idp:acr:static-code", "PIN", "PIN", "Static PIN/code the holder set at activation."},
	{"mosip:idp:acr:generated-code", "OTP", "OTP", "One-time code sent to the holder's email or phone."},
	{"mosip:idp:acr:linked-wallet", "Wallet", "WLA", "Approve sign-in from a linked Inji wallet."},
	{"mosip:idp:acr:biometrics", "Biometrics", "BIO", "L1 biometric device capture."},
	{"mosip:idp:acr:knowledge", "Knowledge", "KBI", "Knowledge-based answers."},
	{"mosip:idp:acr:password", "Password", "PWD", "Password credential."},
	{"mosip:idp:acr:id-token", "ID token", "IDT", "Federated ID-token assertion."},
}

// Deployment-configurable eSignet plumbing. Defaults match the injiweb compose
// profile; a different deployment overrides via env so verifiably stays
// implementation-agnostic.
func esignetDBContainer() string    { return envOr("ESIGNET_DB_CONTAINER", "injiweb-postgres") }
func esignetRedisContainer() string { return envOr("ESIGNET_REDIS_CONTAINER", "injiweb-redis") }
func esignetDBName() string         { return envOr("ESIGNET_DB_NAME", "mosip_esignet") }
func esignetDBUser() string         { return envOr("ESIGNET_DB_USER", "postgres") }

// esignetTargetClientID is the eSignet OIDC client whose factors we configure —
// the same client the in-app auth-code flow authenticates with.
func esignetTargetClientID() string { return injiAuthcodeClientID() }

// esignetBackedACRs is the set of ACRs this deployment actually has wired and
// is therefore safe to enable — requesting an unbacked ACR breaks eSignet login.
// Defaults to PIN+OTP+Wallet (the mock-identity deployment); widen via
// ESIGNET_BACKED_ACRS (space- or comma-separated) when more plugins are present.
func esignetBackedACRs() map[string]bool {
	raw := strings.TrimSpace(os.Getenv("ESIGNET_BACKED_ACRS"))
	if raw == "" {
		raw = "mosip:idp:acr:static-code mosip:idp:acr:generated-code mosip:idp:acr:linked-wallet"
	}
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' }) {
		if f = strings.TrimSpace(f); f != "" {
			out[f] = true
		}
	}
	return out
}

// dockerExecCapture runs cmd inside a sibling container over the mounted docker
// socket (POST /containers/{id}/exec then POST /exec/{id}/start) and returns its
// demultiplexed stdout. Same unix-socket transport as dockerRestart. Non-Tty, so
// the start stream is Docker's multiplexed frame format (see demuxDockerStream).
// Returns an error carrying stderr when the exec exits non-zero.
func dockerExecCapture(ctx context.Context, container string, cmd []string) (string, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
	}}
	cl := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	// 1) create the exec instance.
	createBody, _ := json.Marshal(map[string]any{
		"AttachStdout": true, "AttachStderr": true, "Tty": false, "Cmd": cmd,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://unix/containers/"+container+"/exec", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return "", fmt.Errorf("docker exec create (%s): %w", container, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("docker exec create (%s): %d: %s", container, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("docker exec create decode: %w", err)
	}
	if created.ID == "" {
		return "", fmt.Errorf("docker exec create (%s): empty exec id", container)
	}

	// 2) start it and read the whole (multiplexed) output stream.
	startBody, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	sreq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://unix/exec/"+created.ID+"/start", bytes.NewReader(startBody))
	sreq.Header.Set("Content-Type", "application/json")
	sresp, err := cl.Do(sreq)
	if err != nil {
		return "", fmt.Errorf("docker exec start (%s): %w", container, err)
	}
	defer sresp.Body.Close()
	raw, err := io.ReadAll(sresp.Body)
	if err != nil {
		return "", fmt.Errorf("docker exec read (%s): %w", container, err)
	}
	stdout, stderr := demuxDockerStream(raw)

	// 3) check the exit code.
	ireq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/exec/"+created.ID+"/json", nil)
	if iresp, ierr := cl.Do(ireq); ierr == nil {
		defer iresp.Body.Close()
		var info struct {
			ExitCode int `json:"ExitCode"`
		}
		if json.NewDecoder(iresp.Body).Decode(&info) == nil && info.ExitCode != 0 {
			msg := strings.TrimSpace(stderr)
			if msg == "" {
				msg = strings.TrimSpace(stdout)
			}
			return stdout, fmt.Errorf("%s exited %d: %s", container, info.ExitCode, msg)
		}
	}
	return stdout, nil
}

// demuxDockerStream splits Docker's multiplexed exec stream into stdout/stderr.
// Frame header: [stream(1B)][0][0][0][size uint32 BE], then size payload bytes;
// stream 1 = stdout, 2 = stderr. A body that isn't framed (e.g. a raw Tty
// stream) is returned verbatim as stdout.
func demuxDockerStream(b []byte) (stdout, stderr string) {
	if len(b) < 8 || b[0] > 2 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return string(b), ""
	}
	var out, errb bytes.Buffer
	i := 0
	for i+8 <= len(b) {
		st := b[i]
		size := int(binary.BigEndian.Uint32(b[i+4 : i+8]))
		i += 8
		if size > len(b)-i {
			size = len(b) - i
		}
		payload := b[i : i+size]
		i += size
		if st == 2 {
			errb.Write(payload)
		} else {
			out.Write(payload)
		}
	}
	return out.String(), errb.String()
}

// readESignetClientACRs reads the target client's registered authContextRefs
// from the eSignet Postgres (client_detail.acr_values, a JSON array string).
func readESignetClientACRs(ctx context.Context) ([]string, error) {
	client := esignetTargetClientID()
	sql := fmt.Sprintf("SELECT acr_values FROM client_detail WHERE id='%s'", client)
	out, err := dockerExecCapture(ctx, esignetDBContainer(),
		[]string{"psql", "-U", esignetDBUser(), "-d", esignetDBName(), "-tAX", "-c", sql})
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, fmt.Errorf("client %q not found in eSignet client_detail", client)
	}
	var acrs []string
	if err := json.Unmarshal([]byte(out), &acrs); err != nil {
		return nil, fmt.Errorf("parse acr_values %q: %w", out, err)
	}
	return acrs, nil
}

// writeESignetClientACRs sets the target client's authContextRefs and flushes
// eSignet's Redis client-detail cache so the change takes effect with no restart.
func writeESignetClientACRs(ctx context.Context, acrs []string) error {
	blob, err := json.Marshal(acrs) // ["a","b"] — values are allowlisted ACRs (no quotes), safe to inline.
	if err != nil {
		return err
	}
	client := esignetTargetClientID()
	sql := fmt.Sprintf("UPDATE client_detail SET acr_values='%s', upd_dtimes=now() WHERE id='%s'", string(blob), client)
	if _, err := dockerExecCapture(ctx, esignetDBContainer(),
		[]string{"psql", "-U", esignetDBUser(), "-d", esignetDBName(), "-tAX", "-c", sql}); err != nil {
		return fmt.Errorf("update acr_values: %w", err)
	}
	// eSignet caches client_detail in Redis and does not invalidate on external
	// DB writes — flush the entry so the new factors are live immediately.
	if _, err := dockerExecCapture(ctx, esignetRedisContainer(),
		[]string{"redis-cli", "DEL", "clientdetails::" + client}); err != nil {
		return fmt.Errorf("acr_values updated but cache flush failed (waits for TTL): %w", err)
	}
	return nil
}

// esignetACRCache caches the enabled acr_values so StartInjiClaim doesn't shell
// into the eSignet DB on every claim. Sourced from the client registration on
// first read and refreshed on every save.
var esignetACRCache = struct {
	sync.RWMutex
	vals   []string
	loaded bool
}{}

func setESignetACRCache(acrs []string) {
	esignetACRCache.Lock()
	esignetACRCache.vals = append([]string(nil), acrs...)
	esignetACRCache.loaded = true
	esignetACRCache.Unlock()
}

// injiAuthcodeACRValues returns the space-joined acr_values verifiably requests
// at /authorize — the enabled login factors. Cached from the eSignet client
// registration; falls back to the INJI_AUTHCODE_ACR env default when the
// registration can't be read, so the claim flow keeps working even if the docker
// socket or eSignet DB is unavailable.
func (h *H) injiAuthcodeACRValues() string {
	esignetACRCache.RLock()
	loaded, vals := esignetACRCache.loaded, esignetACRCache.vals
	esignetACRCache.RUnlock()
	if loaded {
		if v := strings.Join(vals, " "); v != "" {
			return v
		}
		return injiAuthcodeACR()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	acrs, err := readESignetClientACRs(ctx)
	if err != nil || len(acrs) == 0 {
		return injiAuthcodeACR() // env fallback; don't poison the cache on failure.
	}
	setESignetACRCache(acrs)
	return strings.Join(acrs, " ")
}

// sortACRsByDisplay orders ACRs by their position in esignetAllFactors.
func sortACRsByDisplay(acrs []string) []string {
	order := map[string]int{}
	for i, f := range esignetAllFactors {
		order[f.ACR] = i
	}
	out := append([]string(nil), acrs...)
	sort.SliceStable(out, func(i, j int) bool { return order[out[i]] < order[out[j]] })
	return out
}

// acrNames maps ACR values to their human labels (for status messages).
func acrNames(acrs []string) []string {
	name := map[string]string{}
	for _, f := range esignetAllFactors {
		name[f.ACR] = f.Name
	}
	out := make([]string, 0, len(acrs))
	for _, a := range acrs {
		if n := name[a]; n != "" {
			out = append(out, n)
		} else {
			out = append(out, a)
		}
	}
	return out
}

// esignetFactorVM is the per-factor view model the template renders.
type esignetFactorVM struct {
	ACR     string
	Name    string
	AMR     string
	Desc    string
	Enabled bool
	Backed  bool
}

// esignetConfigData builds the config page view model: every factor with its
// enabled (from the live client registration) and backed (safe-to-enable) flags,
// plus the target client id and any read error / status notice.
func (h *H) esignetConfigData(ctx context.Context, notice string) map[string]any {
	backed := esignetBackedACRs()
	enabled := map[string]bool{}
	var readErr string
	if acrs, err := readESignetClientACRs(ctx); err != nil {
		readErr = err.Error()
	} else {
		for _, a := range acrs {
			enabled[a] = true
		}
		setESignetACRCache(acrs)
	}
	factors := make([]esignetFactorVM, 0, len(esignetAllFactors))
	for _, f := range esignetAllFactors {
		factors = append(factors, esignetFactorVM{
			ACR: f.ACR, Name: f.Name, AMR: f.AMR, Desc: f.Desc,
			Enabled: enabled[f.ACR], Backed: backed[f.ACR],
		})
	}
	return map[string]any{
		"Factors":   factors,
		"ClientID":  esignetTargetClientID(),
		"ReadError": readErr,
		"Notice":    notice,
	}
}

// ShowEsignetConfig renders the eSignet auth-method (login-factor) config page.
// Admin-gated, like the other /admin/* surfaces.
func (h *H) ShowEsignetConfig(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	h.render(w, r, "admin_esignet", h.pageData(sess, h.esignetConfigData(r.Context(), "")))
}

// SaveEsignetConfig persists the selected login factors to the eSignet client
// registration (and the request-time cache). POST /admin/esignet.
func (h *H) SaveEsignetConfig(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "Bad form: "+err.Error())
		return
	}
	known := map[string]bool{}
	for _, f := range esignetAllFactors {
		known[f.ACR] = true
	}
	backed := esignetBackedACRs()
	// Only accept known + backed factors: never enable an unbacked ACR (it would
	// break eSignet login) and never write an arbitrary string into the DB.
	var selected []string
	seen := map[string]bool{}
	for _, a := range r.Form["acr"] {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] || !known[a] || !backed[a] {
			continue
		}
		seen[a] = true
		selected = append(selected, a)
	}
	if len(selected) == 0 {
		h.render(w, r, "admin_esignet", h.pageData(sess,
			h.esignetConfigData(r.Context(), "⚠ Select at least one login factor — saving none would lock everyone out.")))
		return
	}
	selected = sortACRsByDisplay(selected)
	if err := writeESignetClientACRs(r.Context(), selected); err != nil {
		h.render(w, r, "admin_esignet", h.pageData(sess,
			h.esignetConfigData(r.Context(), "✗ Save failed: "+err.Error())))
		return
	}
	setESignetACRCache(selected)
	h.render(w, r, "admin_esignet", h.pageData(sess,
		h.esignetConfigData(r.Context(), "✓ Saved. eSignet now offers: "+strings.Join(acrNames(selected), ", ")+
			". Takes effect on the next login — no restart.")))
}
