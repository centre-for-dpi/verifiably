package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/jobs"
	"github.com/verifiably/verifiably-go/vctypes"
)

// delegBulkAdapter records SaveCustomSchema/IssueToWallet calls and fails the
// Nth call of each on demand.
type delegBulkAdapter struct {
	backend.Adapter
	saved, issued         int
	failSaveOn, failIssue int // 1-based call index that returns the error; 0 = never
	issueReqs             []backend.IssueRequest
	noDpgs                bool
}

func (a *delegBulkAdapter) SaveCustomSchema(context.Context, vctypes.Schema) error {
	a.saved++
	if a.saved == a.failSaveOn {
		return errors.New("save refused")
	}
	return nil
}
func (a *delegBulkAdapter) IssueToWallet(_ context.Context, r backend.IssueRequest) (backend.IssueToWalletResult, error) {
	a.issued++
	a.issueReqs = append(a.issueReqs, r)
	if a.issued == a.failIssue {
		return backend.IssueToWalletResult{}, errors.New("wallet refused")
	}
	return backend.IssueToWalletResult{OfferURI: "openid-credential-offer://" + r.Schema.Name, PIN: "0000"}, nil
}
func (a *delegBulkAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	if a.noDpgs {
		return nil, nil
	}
	return map[string]vctypes.DPG{"dpg1": {}}, nil
}

func delegBulkReq(subjectRef, std string) apiDelegationIssueRequest {
	r := apiDelegationIssueRequest{IssuerDpg: "dpg1", IssuerDID: "did:example:issuer", Std: std}
	r.Subject.SubjectRef = subjectRef
	r.Subject.Claims = map[string]string{"givenName": "Ada"}
	r.Delegation.DelegateID = "did:example:delegate"
	r.Delegation.Role = "Guardian"
	return r
}

func TestRegisterDelegationSchemas(t *testing.T) {
	h := apiTestH(&delegBulkAdapter{})
	subj, deleg, err := h.registerDelegationSchemas(context.Background(), "dpg1", "Person", "Delegated", "w3c_vcdm_2")
	if err != nil || subj.Name != "Person" || deleg.Name != "Delegated" {
		t.Fatalf("ok case: subj=%+v deleg=%+v err=%v", subj, deleg, err)
	}
	h = apiTestH(&delegBulkAdapter{failSaveOn: 1})
	if _, _, err := h.registerDelegationSchemas(context.Background(), "dpg1", "Person", "Delegated", "w3c_vcdm_2"); err == nil || !strings.Contains(err.Error(), "register subject schema: save refused") {
		t.Errorf("first save failure: err=%v", err)
	}
	h = apiTestH(&delegBulkAdapter{failSaveOn: 2})
	if _, _, err := h.registerDelegationSchemas(context.Background(), "dpg1", "Person", "Delegated", "w3c_vcdm_2"); err == nil || !strings.Contains(err.Error(), "register delegation schema: save refused") {
		t.Errorf("second save failure: err=%v", err)
	}
}

func TestIssueDelegationPairCore(t *testing.T) {
	subj := delegationCredSchema("Person", "dpg1", []string{"subjectRef", "givenName"}, "w3c_vcdm_2")
	deleg := delegationCredSchema("Delegated", "dpg1", []string{"onBehalfOf", "role", "delegation"}, "w3c_vcdm_2")

	t.Run("w3c with status list binding", func(t *testing.T) {
		ad := &delegBulkAdapter{}
		h := apiTestH(ad)
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "bs", allocIndex: 7}, Kind: "bitstring"})
		h.StatusLists = set
		out, err := h.issueDelegationPairCore(context.Background(), "test", delegBulkReq("urn:person:1", "w3c_vcdm_2"), subj, deleg)
		if err != nil {
			t.Fatal(err)
		}
		if out.Subject.Type != "Person" || out.Delegation.Type != "Delegated" || out.Subject.OfferURI != "openid-credential-offer://Person" || out.Delegation.PIN != "0000" {
			t.Errorf("result = %+v", out)
		}
		if out.StatusListIndex != 7 || out.StatusListCredential != "https://issuer.example/status/bs" {
			t.Errorf("status list binding not surfaced: %+v", out)
		}
		if len(ad.issueReqs) != 2 || ad.issueReqs[1].StatusList == nil || ad.issueReqs[1].StatusList.Index != 7 {
			t.Fatalf("issue requests = %+v", ad.issueReqs)
		}
		if body := string(ad.issueReqs[1].CredentialData); !strings.Contains(body, `"statusListIndex"`) && !strings.Contains(body, "credentialStatus") {
			t.Errorf("delegation VC must embed the status entry: %s", body)
		}
		if body := string(ad.issueReqs[0].CredentialData); !strings.Contains(body, `"subjectRef":"urn:person:1"`) {
			t.Errorf("subject VC body = %s", body)
		}
	})
	t.Run("sd-jwt uses flat claims", func(t *testing.T) {
		ad := &delegBulkAdapter{}
		h := apiTestH(ad)
		out, err := h.issueDelegationPairCore(context.Background(), "test", delegBulkReq("urn:person:2", "sd_jwt_vc (IETF)"), subj, deleg)
		if err != nil {
			t.Fatal(err)
		}
		if out.StatusListCredential != "" {
			t.Errorf("no status list wired: binding must be empty, got %+v", out)
		}
		if ad.issueReqs[0].SubjectData["subjectRef"] != "urn:person:2" || ad.issueReqs[0].CredentialData != nil {
			t.Errorf("subject SD-JWT request = %+v", ad.issueReqs[0])
		}
		if ad.issueReqs[1].SubjectData["onBehalfOf"] != "urn:person:2" || ad.issueReqs[1].SubjectData["role"] != "Guardian" {
			t.Errorf("delegation SD-JWT request = %+v", ad.issueReqs[1])
		}
	})
	t.Run("subject issue error", func(t *testing.T) {
		h := apiTestH(&delegBulkAdapter{failIssue: 1})
		_, err := h.issueDelegationPairCore(context.Background(), "test", delegBulkReq("urn:person:3", "w3c_vcdm_2"), subj, deleg)
		if err == nil || !strings.Contains(err.Error(), "issue subject credential: wallet refused") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("delegation issue error", func(t *testing.T) {
		h := apiTestH(&delegBulkAdapter{failIssue: 2})
		_, err := h.issueDelegationPairCore(context.Background(), "test", delegBulkReq("urn:person:4", "w3c_vcdm_2"), subj, deleg)
		if err == nil || !strings.Contains(err.Error(), "issue delegation credential: wallet refused") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("status list allocate error", func(t *testing.T) {
		h := apiTestH(&delegBulkAdapter{})
		set := NewStatusListSet()
		set.Register(&StatusListEntry{Store: &slFakeStore{id: "bs", allocErr: errors.New("full")}, Kind: "bitstring"})
		h.StatusLists = set
		_, err := h.issueDelegationPairCore(context.Background(), "test", delegBulkReq("urn:person:5", "w3c_vcdm_2"), subj, deleg)
		if err == nil || !strings.Contains(err.Error(), "status list: status list allocate: full") {
			t.Errorf("err = %v", err)
		}
	})
}

func delegBulkH(t *testing.T, ad backend.Adapter) *H {
	t.Helper()
	h := apiTestH(ad)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.BulkJobQueue = jobs.NewQueue(ctx, nil, 1)
	return h
}

func TestAPIDelegationIssueBulk_Guards(t *testing.T) {
	t.Run("unauthenticated", func(t *testing.T) {
		h := delegBulkH(t, &delegBulkAdapter{})
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, httptest.NewRequest(http.MethodPost, "/api/v1/delegation/issue/bulk", strings.NewReader("{}")))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("rate limited", func(t *testing.T) {
		h := delegBulkH(t, &delegBulkAdapter{})
		h.RateLimiter = &RateLimiter{keyLimit: 0, ipLimit: 1, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{}))
		if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "60" {
			t.Fatalf("status = %d headers=%v", rr.Code, rr.Header())
		}
	})
	t.Run("no queue", func(t *testing.T) {
		h := apiTestH(&delegBulkAdapter{})
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{}))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "bulk job queue not configured") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		h := delegBulkH(t, &delegBulkAdapter{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/delegation/issue/bulk", strings.NewReader("{"))
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid JSON") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("rows required", func(t *testing.T) {
		h := delegBulkH(t, &delegBulkAdapter{})
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{"rows": []any{}}))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "rows required") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("no issuer DPG", func(t *testing.T) {
		h := delegBulkH(t, &delegBulkAdapter{noDpgs: true})
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{"rows": []any{map[string]any{"subjectRef": "x"}}}))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "no issuer DPG available") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("schema registration fails", func(t *testing.T) {
		h := delegBulkH(t, &delegBulkAdapter{failSaveOn: 1})
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{"rows": []any{map[string]any{"subjectRef": "x"}}}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "register subject schema: save refused") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("row without subjectRef", func(t *testing.T) {
		ad := &delegBulkAdapter{}
		h := delegBulkH(t, ad)
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{
			"rows": []any{map[string]any{"subjectRef": "ok"}, map[string]any{"subjectRef": "  "}}}))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "each row needs subjectRef") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
		if ad.issued != 0 {
			t.Errorf("nothing may be issued when validation fails")
		}
	})
	t.Run("queue submit fails", func(t *testing.T) {
		// A pool that dials an unreachable Postgres makes Submit's INSERT fail
		// fast (connect_timeout=1, port 1 → connection refused).
		pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db?connect_timeout=1&sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		h := apiTestH(&delegBulkAdapter{})
		h.BulkJobQueue = jobs.NewQueue(ctx, pool, 1)
		rr := httptest.NewRecorder()
		h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{"rows": []any{map[string]any{"subjectRef": "x"}}}))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "submit bulk job: jobs: insert:") {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

// Rows carry per-subject claims and allowedAction through the queue's flat
// string map and back into a full pair request.
func TestAPIDelegationIssueBulk_RowMappingRoundTrip(t *testing.T) {
	ad := &delegBulkAdapter{}
	h := delegBulkH(t, ad)
	rr := httptest.NewRecorder()
	h.APIDelegationIssueBulk(rr, authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{
		"issuerDid": "did:example:issuer",
		"rows": []any{map[string]any{
			"subjectRef": "urn:person:9", "delegateId": "did:example:d", "role": "Guardian",
			"allowedAction": []string{"present", "consent:disclose"}, "validUntil": "2031-01-01T00:00:00Z",
			"claims": map[string]string{"givenName": "Ada", "familyName": "Lovelace"},
		}},
	}))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeJSON(t, rr.Body.Bytes())
	jobID, _ := resp["jobId"].(string)
	if resp["subjectType"] != "BirthCertificate" || resp["delegationType"] != "DelegatedAccessCredential" ||
		resp["statusUrl"] != "/issuer/issue/bulk/status/"+jobID || resp["total"].(float64) != 1 {
		t.Errorf("response = %v", resp)
	}
	deadline := time.Now().Add(5 * time.Second)
	var job jobs.Job
	for time.Now().Before(deadline) {
		job, _ = h.BulkJobQueue.Status(context.Background(), jobID)
		if job.Status == "done" || job.Status == "error" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if job.Status != "done" || job.Errors != 0 {
		t.Fatalf("job = %+v", job)
	}
	if len(ad.issueReqs) != 2 {
		t.Fatalf("issued %d, want a pair", len(ad.issueReqs))
	}
	subj := string(ad.issueReqs[0].CredentialData)
	if !strings.Contains(subj, `"givenName":"Ada"`) || !strings.Contains(subj, `"familyName":"Lovelace"`) || !strings.Contains(subj, `"subjectRef":"urn:person:9"`) {
		t.Errorf("subject claims did not round-trip: %s", subj)
	}
	deleg := string(ad.issueReqs[1].CredentialData)
	if !strings.Contains(deleg, `"present"`) || !strings.Contains(deleg, `"consent:disclose"`) || !strings.Contains(deleg, `"role":"Guardian"`) ||
		!strings.Contains(deleg, "2031-01-01T00:00:00Z") || !strings.Contains(deleg, "did:example:d") {
		t.Errorf("delegation fields did not round-trip: %s", deleg)
	}
}
