package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// slFakeStore is a statuslist.Backend whose publish methods fail on demand.
type slFakeStore struct {
	statuslist.Backend
	id         string
	jwtErr     error
	vcErr      error
	tokenErr   error
	vc         map[string]any
	allocErr   error
	allocIndex int
	revokeErr  error
	revoked    []int // indexes passed to Revoke
}

func (s *slFakeStore) GetListID() string     { return s.id }
func (s *slFakeStore) GetKind() string       { return "bitstring" }
func (s *slFakeStore) GetPublishURL() string { return "https://issuer.example/status/" + s.id }
func (s *slFakeStore) Allocate() (int, error) {
	return s.allocIndex, s.allocErr
}
func (s *slFakeStore) Revoke(index int) error {
	s.revoked = append(s.revoked, index)
	return s.revokeErr
}
func (s *slFakeStore) PublishBitstringJWT(*statuslist.SigningKey) (string, error) {
	return "jwt", s.jwtErr
}
func (s *slFakeStore) BitstringStatusListVC(string) (map[string]any, error) {
	return s.vc, s.vcErr
}
func (s *slFakeStore) PublishTokenStatusList(*statuslist.SigningKey) (string, error) {
	return "tok", s.tokenErr
}

func slReq(kind, id, accept string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/status-list/"+kind+"/"+id, nil)
	req.SetPathValue("id", id)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return req
}

func slRealStores(t *testing.T) (*statuslist.Store, *statuslist.Store, *statuslist.SigningKey, *statuslist.LDSigner) {
	t.Helper()
	dir := t.TempDir()
	bs, err := statuslist.NewStore("bitstring", "v1", filepath.Join(dir, "bs.json"), "https://issuer.example/status-list/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := statuslist.NewStore("token", "v1", filepath.Join(dir, "tk.json"), "https://issuer.example/status-list/token/v1")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := statuslist.NewSelfSignedKey(dir, "v1")
	if err != nil {
		t.Fatal(err)
	}
	ld, err := statuslist.NewLDSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	return bs, tk, signer, ld
}

func TestStatusListByID_And_For_Fallbacks(t *testing.T) {
	bs, tk, _, _ := slRealStores(t)
	h := &H{StatusLists: NewStatusListSet()}
	if h.statusListByID("bitstring", "") != nil {
		t.Error("empty id must resolve to nil")
	}
	if h.statusListByID("bitstring", "nope") != nil {
		t.Error("unknown id must resolve to nil")
	}
	if h.statusListFor("dpg", "bitstring") != nil || h.statusListFor("dpg", "token") != nil || h.statusListFor("dpg", "other") != nil {
		t.Error("no stores wired: statusListFor must be nil for every kind")
	}
	h.BitstringStore, h.TokenStore = bs, tk
	if e := h.statusListFor("dpg", "bitstring"); e == nil || e.Store != bs || e.Kind != "bitstring" || e.Signer != nil {
		t.Errorf("bitstring fallback = %+v", e)
	}
	if e := h.statusListFor("dpg", "token"); e == nil || e.Store != tk || e.Kind != "token" {
		t.Errorf("token fallback = %+v", e)
	}
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: bs, Kind: "bitstring"})
	h.StatusLists = set
	if e := h.statusListByID("bitstring", "v1"); e == nil || e.Store != bs {
		t.Errorf("registered id must resolve: %+v", e)
	}
	if e := h.statusListFor("any-dpg", "bitstring"); e == nil || e.Store != bs || e.Signer != nil {
		t.Errorf("registered default list must win over the store-only fallback: %+v", e)
	}
}

func TestPublishBitstringStatusList_JWS(t *testing.T) {
	_, _, signer, _ := slRealStores(t)
	t.Run("no signer -> 503", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "a"}, Kind: "bitstring"})
		h := &H{StatusLists: set}
		rr := httptest.NewRecorder()
		h.PublishBitstringStatusList(rr, slReq("bitstring", "a", "application/vc+jwt"))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "signing key unavailable") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("publish error -> 500", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "a", jwtErr: errors.New("boom")}, Signer: signer, Kind: "bitstring"})
		h := &H{StatusLists: set}
		rr := httptest.NewRecorder()
		h.PublishBitstringStatusList(rr, slReq("bitstring", "a", "application/vc+jwt"))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "status list unavailable") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("ok", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "a"}, Signer: signer, Kind: "bitstring"})
		h := &H{StatusLists: set}
		rr := httptest.NewRecorder()
		h.PublishBitstringStatusList(rr, slReq("bitstring", "a", "application/vc+jwt"))
		if rr.Code != http.StatusOK || rr.Body.String() != "jwt" || rr.Header().Get("Content-Type") != "application/vc+jwt" ||
			rr.Header().Get("Cache-Control") != "public, max-age=60" {
			t.Fatalf("status = %d headers=%v body=%s", rr.Code, rr.Header(), rr.Body.String())
		}
	})
}

func TestPublishBitstringStatusList_JSONLD(t *testing.T) {
	bs, _, signer, ld := slRealStores(t)
	t.Run("no ld signer -> 503", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: bs, Signer: signer, Kind: "bitstring"})
		h := &H{StatusLists: set}
		rr := httptest.NewRecorder()
		h.PublishBitstringStatusList(rr, slReq("bitstring", "v1", ""))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "ld signer unavailable") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("build VC error -> 500", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "a", vcErr: errors.New("bad")}, Kind: "bitstring"})
		h := &H{StatusLists: set, StatusLDSigner: ld}
		rr := httptest.NewRecorder()
		h.PublishBitstringStatusList(rr, slReq("bitstring", "a", "*/*"))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("LD sign error -> 500", func(t *testing.T) {
		// A numeric @context is rejected by the JSON-LD processor before any
		// document is loaded — hermetic canonicalization failure.
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "a", vc: map[string]any{"@context": 42, "id": "x"}}, Kind: "bitstring"})
		h := &H{StatusLists: set, StatusLDSigner: ld}
		rr := httptest.NewRecorder()
		h.PublishBitstringStatusList(rr, slReq("bitstring", "a", "*/*"))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "status list unavailable") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("ok -> signed JSON-LD", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: bs, Signer: signer, Kind: "bitstring"})
		h := &H{StatusLists: set, StatusLDSigner: ld}
		rr := httptest.NewRecorder()
		h.PublishBitstringStatusList(rr, slReq("bitstring", "v1", "*/*"))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/vc+ld+json" {
			t.Errorf("Content-Type = %q", ct)
		}
		got := decodeJSON(t, rr.Body.Bytes())
		proof, _ := got["proof"].(map[string]any)
		if proof["type"] != "Ed25519Signature2020" || !strings.HasPrefix(proof["proofValue"].(string), "z") {
			t.Errorf("proof = %v", proof)
		}
		if got["issuer"] != ld.DID() {
			t.Errorf("issuer = %v, want LD signer DID %s", got["issuer"], ld.DID())
		}
	})
}

func TestPublishTokenStatusList(t *testing.T) {
	_, tk, signer, _ := slRealStores(t)
	t.Run("unknown id -> 404", func(t *testing.T) {
		h := &H{StatusLists: NewStatusListSet()}
		rr := httptest.NewRecorder()
		h.PublishTokenStatusList(rr, slReq("token", "zzz", ""))
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "unknown status list id") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("no signer -> 503", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "t"}, Kind: "token"})
		h := &H{StatusLists: set}
		rr := httptest.NewRecorder()
		h.PublishTokenStatusList(rr, slReq("token", "t", ""))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("publish error -> 500", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "t", tokenErr: errors.New("x")}, Signer: signer, Kind: "token"})
		h := &H{StatusLists: set}
		rr := httptest.NewRecorder()
		h.PublishTokenStatusList(rr, slReq("token", "t", ""))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("ok", func(t *testing.T) {
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: tk, Signer: signer, Kind: "token"})
		h := &H{StatusLists: set}
		rr := httptest.NewRecorder()
		h.PublishTokenStatusList(rr, slReq("token", "v1", ""))
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/statuslist+jwt" ||
			rr.Header().Get("Cache-Control") != "public, max-age=60" {
			t.Fatalf("status = %d headers=%v", rr.Code, rr.Header())
		}
		if parts := strings.Split(rr.Body.String(), "."); len(parts) != 3 {
			t.Fatalf("body must be a compact JWT, got %d parts", len(parts))
		}
	})
}
