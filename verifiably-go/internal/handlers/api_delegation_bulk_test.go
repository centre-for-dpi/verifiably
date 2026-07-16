package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/jobs"
	"github.com/verifiably/verifiably-go/vctypes"
)

// bulkTestAdapter counts IssueToWallet / SaveCustomSchema so a fan-out test can
// assert the queue registered the two types ONCE and issued a PAIR per row.
type bulkTestAdapter struct {
	testAdapter
	mu          sync.Mutex
	issued      int
	saved       int
}

func (b *bulkTestAdapter) SaveCustomSchema(_ context.Context, _ vctypes.Schema) error {
	b.mu.Lock()
	b.saved++
	b.mu.Unlock()
	return nil
}
func (b *bulkTestAdapter) IssueToWallet(_ context.Context, _ backend.IssueRequest) (backend.IssueToWalletResult, error) {
	b.mu.Lock()
	b.issued++
	n := b.issued
	b.mu.Unlock()
	return backend.IssueToWalletResult{OfferURI: fmt.Sprintf("openid-credential-offer://%d", n), Flow: "pre_auth"}, nil
}

// TestAPIDelegationIssueBulk_FansOut proves bulk delegated-access issuance:
// N rows -> one job -> a subject+delegation PAIR per row, with the two credential
// types registered exactly twice (once each, not per row).
func TestAPIDelegationIssueBulk_FansOut(t *testing.T) {
	const N = 5
	ad := &bulkTestAdapter{}
	h := apiTestH(ad)
	h.BulkJobQueue = jobs.NewQueue(context.Background(), nil, 3) // in-memory, 3 workers

	rows := make([]map[string]any, 0, N)
	for i := 0; i < N; i++ {
		rows = append(rows, map[string]any{
			"subjectRef":    fmt.Sprintf("urn:person:bulk-%d", i),
			"role":          "Mother",
			"allowedAction": []string{"present", "consent:disclose"},
			"validUntil":    "2033-03-10T00:00:00Z",
		})
	}
	req := authPOST(t, "/api/v1/delegation/issue/bulk", map[string]any{
		"issuerDpg": "dpg1", "std": "w3c_vcdm_2",
		"subjectType": "BirthCertificate", "delegationType": "DelegatedAccessCredential",
		"rows": rows,
	})
	w := httptest.NewRecorder()
	h.APIDelegationIssueBulk(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	resp := decodeJSON(t, w.Body.Bytes())
	jobID, _ := resp["jobId"].(string)
	if jobID == "" {
		t.Fatalf("no jobId in %s", w.Body.String())
	}
	if got := resp["total"].(float64); got != N {
		t.Fatalf("total = %v, want %d", got, N)
	}

	// Poll the job to completion.
	var job jobs.Job
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		job, _ = h.BulkJobQueue.Status(context.Background(), jobID)
		if job.Status == "done" || job.Status == "error" {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if job.Status != "done" {
		t.Fatalf("job status = %q (done=%d errors=%d)", job.Status, job.Done, job.Errors)
	}
	if job.Done != N || job.Errors != 0 {
		t.Fatalf("job done=%d errors=%d, want done=%d errors=0", job.Done, job.Errors, N)
	}

	ad.mu.Lock()
	issued, saved := ad.issued, ad.saved
	ad.mu.Unlock()
	if issued != 2*N {
		t.Fatalf("IssueToWallet called %d times, want %d (a pair per row)", issued, 2*N)
	}
	if saved != 2 {
		t.Fatalf("SaveCustomSchema called %d times, want 2 (both types once, not per row)", saved)
	}
}
