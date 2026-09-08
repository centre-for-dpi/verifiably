package handlers

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// frame builds one Docker multiplexed stream frame.
func frame(stream byte, payload string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:8], uint32(len(payload)))
	return append(h, []byte(payload)...)
}

func TestDemuxDockerStream(t *testing.T) {
	t.Run("framed stdout+stderr", func(t *testing.T) {
		var b bytes.Buffer
		b.Write(frame(1, `["mosip:idp:acr:static-code"]`))
		b.Write(frame(2, "NOTICE: something"))
		b.Write(frame(1, "\n"))
		out, errs := demuxDockerStream(b.Bytes())
		if out != `["mosip:idp:acr:static-code"]`+"\n" {
			t.Fatalf("stdout=%q", out)
		}
		if errs != "NOTICE: something" {
			t.Fatalf("stderr=%q", errs)
		}
	})

	t.Run("raw (non-framed) returned as stdout", func(t *testing.T) {
		raw := []byte("plain psql output no header\n")
		out, errs := demuxDockerStream(raw)
		if out != string(raw) || errs != "" {
			t.Fatalf("out=%q errs=%q", out, errs)
		}
	})

	t.Run("truncated frame is clamped, not panicking", func(t *testing.T) {
		h := make([]byte, 8)
		h[0] = 1
		binary.BigEndian.PutUint32(h[4:8], 100) // claims 100 bytes but only 3 follow
		b := append(h, []byte("abc")...)
		out, _ := demuxDockerStream(b)
		if out != "abc" {
			t.Fatalf("out=%q, want abc", out)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		out, errs := demuxDockerStream(nil)
		if out != "" || errs != "" {
			t.Fatalf("out=%q errs=%q", out, errs)
		}
	})
}

func TestEsignetBackedACRs(t *testing.T) {
	t.Run("default is PIN+OTP+Wallet", func(t *testing.T) {
		t.Setenv("ESIGNET_BACKED_ACRS", "")
		b := esignetBackedACRs()
		for _, want := range []string{"mosip:idp:acr:static-code", "mosip:idp:acr:generated-code", "mosip:idp:acr:linked-wallet"} {
			if !b[want] {
				t.Fatalf("default missing %s", want)
			}
		}
		if b["mosip:idp:acr:biometrics"] {
			t.Fatalf("biometrics should not be backed by default")
		}
	})
	t.Run("env override widens the set (space or comma)", func(t *testing.T) {
		t.Setenv("ESIGNET_BACKED_ACRS", "mosip:idp:acr:static-code, mosip:idp:acr:biometrics")
		b := esignetBackedACRs()
		if !b["mosip:idp:acr:static-code"] || !b["mosip:idp:acr:biometrics"] {
			t.Fatalf("override not honoured: %v", b)
		}
		if b["mosip:idp:acr:generated-code"] {
			t.Fatalf("override should replace, not extend defaults")
		}
	})
}

func TestSortACRsByDisplayAndNames(t *testing.T) {
	in := []string{"mosip:idp:acr:linked-wallet", "mosip:idp:acr:static-code", "mosip:idp:acr:generated-code"}
	got := sortACRsByDisplay(in)
	want := []string{"mosip:idp:acr:static-code", "mosip:idp:acr:generated-code", "mosip:idp:acr:linked-wallet"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sort got %v want %v", got, want)
	}
	// original slice not mutated
	if in[0] != "mosip:idp:acr:linked-wallet" {
		t.Fatalf("input slice was mutated: %v", in)
	}
	names := acrNames(want)
	if !reflect.DeepEqual(names, []string{"PIN", "OTP", "Wallet"}) {
		t.Fatalf("names got %v", names)
	}
	// unknown acr falls back to the raw value
	if n := acrNames([]string{"mosip:idp:acr:unknown"}); n[0] != "mosip:idp:acr:unknown" {
		t.Fatalf("unknown name got %v", n)
	}
}

// ─── deployment plumbing / docker-backed paths ────────────────────────────────

// esignetResetCache clears the package-level ACR cache and restores it after
// the test (the cache is process-global).
func esignetResetCache(t *testing.T) {
	t.Helper()
	esignetACRCache.RLock()
	prevVals, prevLoaded := esignetACRCache.vals, esignetACRCache.loaded
	esignetACRCache.RUnlock()
	esignetACRCache.Lock()
	esignetACRCache.vals, esignetACRCache.loaded = nil, false
	esignetACRCache.Unlock()
	t.Cleanup(func() {
		esignetACRCache.Lock()
		esignetACRCache.vals, esignetACRCache.loaded = prevVals, prevLoaded
		esignetACRCache.Unlock()
	})
}

// esignetCancelledCtx returns an already-cancelled context so every
// dockerExecCapture call fails before touching /var/run/docker.sock.
func esignetCancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestEsignetDeploymentDefaults(t *testing.T) {
	for _, v := range []string{"ESIGNET_DB_CONTAINER", "ESIGNET_REDIS_CONTAINER", "ESIGNET_DB_NAME", "ESIGNET_DB_USER", "INJI_AUTHCODE_CLIENT_ID"} {
		t.Setenv(v, "")
	}
	if esignetDBContainer() != "injiweb-postgres" || esignetRedisContainer() != "injiweb-redis" || esignetDBName() != "mosip_esignet" || esignetDBUser() != "postgres" {
		t.Errorf("defaults: %s %s %s %s", esignetDBContainer(), esignetRedisContainer(), esignetDBName(), esignetDBUser())
	}
	if esignetTargetClientID() != "wallet-demo-client" {
		t.Errorf("target client = %q", esignetTargetClientID())
	}
	t.Setenv("ESIGNET_DB_CONTAINER", " pg-1 ")
	t.Setenv("ESIGNET_REDIS_CONTAINER", "redis-1")
	t.Setenv("ESIGNET_DB_NAME", "esignet")
	t.Setenv("ESIGNET_DB_USER", "app")
	t.Setenv("INJI_AUTHCODE_CLIENT_ID", "client-1")
	if esignetDBContainer() != "pg-1" || esignetRedisContainer() != "redis-1" || esignetDBName() != "esignet" || esignetDBUser() != "app" || esignetTargetClientID() != "client-1" {
		t.Errorf("overrides: %s %s %s %s %s", esignetDBContainer(), esignetRedisContainer(), esignetDBName(), esignetDBUser(), esignetTargetClientID())
	}
}

func TestDockerExecCapture_CancelledContext(t *testing.T) {
	out, err := dockerExecCapture(esignetCancelledCtx(), "pg-1", []string{"true"})
	if err == nil || !strings.HasPrefix(err.Error(), "docker exec create (pg-1): ") || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err = %v", err)
	}
	if out != "" {
		t.Errorf("out = %q", out)
	}
}

func TestReadWriteESignetClientACRs_DockerUnavailable(t *testing.T) {
	ctx := esignetCancelledCtx()
	if acrs, err := readESignetClientACRs(ctx); err == nil || acrs != nil || !strings.Contains(err.Error(), "docker exec create") {
		t.Fatalf("read: %v %v", acrs, err)
	}
	err := writeESignetClientACRs(ctx, []string{"mosip:idp:acr:static-code"})
	if err == nil || !strings.HasPrefix(err.Error(), "update acr_values: docker exec create") {
		t.Fatalf("write: %v", err)
	}
}

func TestSetESignetACRCacheAndACRValues(t *testing.T) {
	esignetResetCache(t)
	t.Setenv("INJI_AUTHCODE_ACR", "mosip:idp:acr:generated-code")
	h := &H{}

	t.Run("loaded cache is joined with spaces", func(t *testing.T) {
		in := []string{"mosip:idp:acr:static-code", "mosip:idp:acr:linked-wallet"}
		setESignetACRCache(in)
		in[0] = "mutated" // the cache must hold its own copy
		if got := h.injiAuthcodeACRValues(); got != "mosip:idp:acr:static-code mosip:idp:acr:linked-wallet" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("loaded but empty → env default", func(t *testing.T) {
		setESignetACRCache(nil)
		if got := h.injiAuthcodeACRValues(); got != "mosip:idp:acr:generated-code" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("not loaded and registration unreadable → env default, cache untouched", func(t *testing.T) {
		esignetResetCache(t)
		// A container name that cannot exist: the exec-create call fails
		// (404 from a daemon, or a dial error without one) and is not cached.
		t.Setenv("ESIGNET_DB_CONTAINER", "verifiably-test-no-such-container-4f1c")
		if got := h.injiAuthcodeACRValues(); got != "mosip:idp:acr:generated-code" {
			t.Errorf("got %q", got)
		}
		esignetACRCache.RLock()
		loaded := esignetACRCache.loaded
		esignetACRCache.RUnlock()
		if loaded {
			t.Error("a failed read must not mark the cache loaded")
		}
	})
}

func TestEsignetConfigData_ReadError(t *testing.T) {
	esignetResetCache(t)
	t.Setenv("ESIGNET_BACKED_ACRS", "mosip:idp:acr:static-code")
	t.Setenv("INJI_AUTHCODE_CLIENT_ID", "client-1")
	data := (&H{}).esignetConfigData(esignetCancelledCtx(), "hello")
	if data["ClientID"] != "client-1" || data["Notice"] != "hello" {
		t.Errorf("data = %v", data)
	}
	if re, _ := data["ReadError"].(string); !strings.Contains(re, "docker exec create") {
		t.Errorf("ReadError = %q", re)
	}
	factors := data["Factors"].([]esignetFactorVM)
	if len(factors) != len(esignetAllFactors) {
		t.Fatalf("factors = %d", len(factors))
	}
	for _, f := range factors {
		if f.Enabled {
			t.Errorf("%s enabled without a readable registration", f.ACR)
		}
		if want := f.ACR == "mosip:idp:acr:static-code"; f.Backed != want {
			t.Errorf("%s backed = %v want %v", f.ACR, f.Backed, want)
		}
	}
}

func esignetNewH(t *testing.T) *H {
	t.Helper()
	return &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "admin_esignet")}
}

func esignetReq(method string, form url.Values, cookies ...*http.Cookie) *http.Request {
	var req *http.Request
	if method == http.MethodGet {
		req = httptest.NewRequest(http.MethodGet, "/admin/esignet", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
	} else {
		req = formPost("/admin/esignet", form, cookies...)
	}
	req.Header.Set("HX-Request", "true")
	req.Header.Set("HX-Target", "main")
	return req.WithContext(esignetCancelledCtx())
}

func TestShowEsignetConfig(t *testing.T) {
	esignetResetCache(t)
	h := esignetNewH(t)
	t.Run("non-admin → login redirect", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ShowEsignetConfig(rr, esignetReq(http.MethodGet, nil))
		if rr.Header().Get("HX-Redirect") != "/admin/login" {
			t.Fatalf("HX-Redirect = %q (status %d)", rr.Header().Get("HX-Redirect"), rr.Code)
		}
	})
	t.Run("admin renders factors and the read warning", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_CLIENT_ID", "client-1")
		cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = true })
		rr := httptest.NewRecorder()
		h.ShowEsignetConfig(rr, esignetReq(http.MethodGet, nil, cookies...))
		body := rr.Body.String()
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		for _, want := range []string{"client-1", "Could not read the current eSignet configuration", `value="mosip:idp:acr:static-code"`, "not wired in this deployment", `action="/admin/esignet"`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %q", want)
			}
		}
	})
}

func TestSaveEsignetConfig(t *testing.T) {
	esignetResetCache(t)
	t.Setenv("ESIGNET_BACKED_ACRS", "")
	h := esignetNewH(t)
	admin := seedSession(t, h, func(s *Session) { s.IsAdmin = true })

	t.Run("non-admin → login redirect", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.SaveEsignetConfig(rr, esignetReq(http.MethodPost, url.Values{"acr": {"mosip:idp:acr:static-code"}}))
		if rr.Header().Get("HX-Redirect") != "/admin/login" {
			t.Fatalf("HX-Redirect = %q", rr.Header().Get("HX-Redirect"))
		}
	})
	t.Run("malformed form → toast", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/esignet", strings.NewReader("acr=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("HX-Request", "true")
		for _, c := range admin {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.SaveEsignetConfig(rr, req)
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "Bad form:") {
			t.Fatalf("HX-Trigger = %q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("unknown, unbacked, blank and duplicate factors are dropped → lock-out warning", func(t *testing.T) {
		form := url.Values{"acr": {"", "  ", "not:an:acr", "mosip:idp:acr:biometrics", "mosip:idp:acr:biometrics"}}
		rr := httptest.NewRecorder()
		h.SaveEsignetConfig(rr, esignetReq(http.MethodPost, form, admin...))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Select at least one login factor") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("write failure renders the save error", func(t *testing.T) {
		form := url.Values{"acr": {"mosip:idp:acr:linked-wallet", "mosip:idp:acr:static-code", "mosip:idp:acr:static-code"}}
		rr := httptest.NewRecorder()
		h.SaveEsignetConfig(rr, esignetReq(http.MethodPost, form, admin...))
		body := rr.Body.String()
		if rr.Code != http.StatusOK || !strings.Contains(body, "✗ Save failed: update acr_values: docker exec create") {
			t.Fatalf("got %d %q", rr.Code, body)
		}
		esignetACRCache.RLock()
		loaded := esignetACRCache.loaded
		esignetACRCache.RUnlock()
		if loaded {
			t.Error("a failed save must not update the cache")
		}
	})
}
