// Package jobs implements an async bulk-issuance job queue. Jobs are stored
// in the bulk_jobs PostgreSQL table when a pool is available; otherwise an
// in-memory map is used (single-process only, jobs lost on restart).
//
// API surface exposed to handlers:
//
//	q.Submit(ctx, rows, schemaID, issuerDpg, ownerKey) → jobID
//	q.Status(ctx, jobID) → Job
//	q.Progress(ctx, jobID) → <-chan Progress (SSE-ready)
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Status values for a bulk job.
const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusError   = "error"
)

// Job represents a single bulk-issuance job.
type Job struct {
	ID        string
	Status    string
	Total     int
	Done      int
	Errors    int
	ErrorMsg  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Progress is the payload emitted to SSE subscribers.
type Progress struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
	Total  int    `json:"total"`
	Done   int    `json:"done"`
	Errors int    `json:"errors"`
}

// Rows is a slice of credential subject maps, one per credential to issue.
type Rows = []map[string]string

// WorkFn is the per-row function the worker calls. It returns an error if
// the credential could not be issued.
type WorkFn func(ctx context.Context, row map[string]string) error

// Queue manages bulk job submission, status tracking, and progress broadcast.
type Queue struct {
	ctx  context.Context // shutdown signal; passed to workFn so adapters can abort
	pool *pgxpool.Pool   // nil = in-memory only

	mu      sync.Mutex
	jobs    map[string]*Job
	subs    map[string][]chan Progress // jobID → subscriber channels
	pending chan *jobTask
}

type jobTask struct {
	job    *Job
	rows   Rows
	workFn WorkFn
}

// NewQueue creates a Queue. When pool is nil an in-memory store is used.
// ctx is the server's shutdown context: workers pass it to every workFn call
// so in-flight adapter requests are cancelled on graceful shutdown.
// workerCount goroutines process jobs concurrently.
func NewQueue(ctx context.Context, pool *pgxpool.Pool, workerCount int) *Queue {
	q := &Queue{
		ctx:     ctx,
		pool:    pool,
		jobs:    map[string]*Job{},
		subs:    map[string][]chan Progress{},
		pending: make(chan *jobTask, 256),
	}
	for i := 0; i < workerCount; i++ {
		go q.worker()
	}
	if pool != nil {
		go q.cleanupLoop()
	}
	return q
}

// cleanupLoop deletes completed/errored bulk_jobs rows older than 7 days.
// Runs once per hour; exits when the server shutdown context is cancelled.
func (q *Queue) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, _ = q.pool.Exec(ctx, `
				DELETE FROM bulk_jobs
				WHERE status IN ('done','error')
				  AND updated_at < now() - INTERVAL '7 days'`)
			cancel()
		case <-q.ctx.Done():
			return
		}
	}
}

// Submit enqueues a new bulk job and returns its ID immediately (HTTP 202).
// workFn is called once per row inside the background worker.
func (q *Queue) Submit(ctx context.Context, rows Rows, workFn WorkFn) (string, error) {
	id := newJobID()
	job := &Job{
		ID:        id,
		Status:    StatusPending,
		Total:     len(rows),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	q.mu.Lock()
	q.jobs[id] = job
	q.mu.Unlock()

	if q.pool != nil {
		_, err := q.pool.Exec(ctx, `
			INSERT INTO bulk_jobs (id, status, total, done, errors, error_msg)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			id, StatusPending, len(rows), 0, 0, "",
		)
		if err != nil {
			return "", fmt.Errorf("jobs: insert: %w", err)
		}
	}

	select {
	case q.pending <- &jobTask{job: job, rows: rows, workFn: workFn}:
	default:
		// All 256 queue slots and all workers are occupied. Remove the in-memory
		// record and the PG row so there is no orphaned job entry.
		q.mu.Lock()
		delete(q.jobs, id)
		q.mu.Unlock()
		if q.pool != nil {
			_, _ = q.pool.Exec(ctx, `DELETE FROM bulk_jobs WHERE id = $1`, id)
		}
		return "", fmt.Errorf("jobs: queue full — try again later")
	}
	return id, nil
}

// Status returns the current job state.
func (q *Queue) Status(ctx context.Context, id string) (Job, bool) {
	if q.pool != nil {
		j, ok := q.loadFromDB(ctx, id)
		if ok {
			return j, true
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return Job{}, false
	}
	return *j, true
}

// Subscribe returns a channel that receives progress updates until the job
// finishes or ctx is cancelled. The channel is closed when done.
//
// close(ch) runs under q.mu — must stay aligned with the lock held in
// broadcast around the send — otherwise broadcast can send on a closed
// channel and panic.
func (q *Queue) Subscribe(ctx context.Context, id string) <-chan Progress {
	ch := make(chan Progress, 16)
	q.mu.Lock()
	q.subs[id] = append(q.subs[id], ch)
	q.mu.Unlock()
	go func() {
		<-ctx.Done()
		q.mu.Lock()
		subs := q.subs[id]
		for i, s := range subs {
			if s == ch {
				q.subs[id] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		close(ch)
		q.mu.Unlock()
	}()
	return ch
}

func (q *Queue) worker() {
	for task := range q.pending {
		q.run(task)
	}
}

func (q *Queue) run(task *jobTask) {
	job := task.job
	q.setStatus(job, StatusRunning)

	for _, row := range task.rows {
		if q.ctx.Err() != nil {
			// Server is shutting down — stop issuing and mark the job as errored.
			q.mu.Lock()
			job.ErrorMsg = "server shutdown"
			q.mu.Unlock()
			q.setStatus(job, StatusError)
			return
		}
		err := task.workFn(q.ctx, row)
		q.mu.Lock()
		job.Done++
		job.UpdatedAt = time.Now().UTC()
		if err != nil {
			job.Errors++
		}
		q.mu.Unlock()
		q.broadcast(job)
		q.persistProgress(q.ctx, job)
	}

	q.setStatus(job, StatusDone)
}

func (q *Queue) setStatus(job *Job, status string) {
	q.mu.Lock()
	job.Status = status
	job.UpdatedAt = time.Now().UTC()
	q.mu.Unlock()
	q.broadcast(job)
	if q.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = q.pool.Exec(ctx, `
			UPDATE bulk_jobs SET status=$1, updated_at=now() WHERE id=$2`,
			status, job.ID)
	}
}

func (q *Queue) persistProgress(ctx context.Context, job *Job) {
	if q.pool == nil {
		return
	}
	q.mu.Lock()
	done := job.Done
	errs := job.Errors
	q.mu.Unlock()
	_, _ = q.pool.Exec(ctx, `
		UPDATE bulk_jobs SET done=$1, errors=$2, updated_at=now() WHERE id=$3`,
		done, errs, job.ID)
}

func (q *Queue) broadcast(job *Job) {
	q.mu.Lock()
	defer q.mu.Unlock()
	p := Progress{
		JobID:  job.ID,
		Status: job.Status,
		Total:  job.Total,
		Done:   job.Done,
		Errors: job.Errors,
	}
	// Send under the lock so an unsubscribing goroutine (which closes the
	// channel under the same lock — see Subscribe) cannot close between
	// our membership check and the send. `select default` keeps each send
	// non-blocking, so a slow consumer cannot stall the worker.
	for _, ch := range q.subs[job.ID] {
		select {
		case ch <- p:
		default:
		}
	}
}

func (q *Queue) loadFromDB(ctx context.Context, id string) (Job, bool) {
	var j Job
	err := q.pool.QueryRow(ctx, `
		SELECT id, status, total, done, errors, error_msg, created_at, updated_at
		FROM bulk_jobs WHERE id = $1`, id,
	).Scan(&j.ID, &j.Status, &j.Total, &j.Done, &j.Errors,
		&j.ErrorMsg, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		return Job{}, false
	}
	return j, true
}

func newJobID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "job-" + hex.EncodeToString(b)
}
