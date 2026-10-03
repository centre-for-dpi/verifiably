// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

// Key names one version of a schema.
type Key struct {
	// ID is the schema id.
	ID string
	// Version is the version number.
	Version int
}

// String names the version for a log line.
func (k Key) String() string { return fmt.Sprintf("%s version %d", k.ID, k.Version) }

// Failure is one version whose registration the stack refused for good.
type Failure struct {
	// Key names the version.
	Key Key
	// Err is the refusal of the stack.
	Err error
}

// Outcome is what one run of Republish did.
type Outcome struct {
	// Done counts the versions the stack took.
	Done int
	// Retry lists the versions the stack could take later: it answered
	// unavailable or deadline exceeded.
	Retry []Key
	// Failed lists the versions the stack refused with any other code.
	// The detail page of each shows the reason.
	Failed []Failure
}

// maxReason caps the reason the detail page shows.
const maxReason = 300

// Republish registers published versions with the DPG again (ADR-077).
// A stack can keep a registration of an earlier release, such as a
// walt.id configuration with the retired vct. The registration of the
// registry then replaces it. Every adapter takes the same registration
// twice without a second write, so the registry runs this at each start.
// With only nil it registers every published version, else the listed
// versions that are still published. A draft and a retired version
// stay out.
func (s *Service) Republish(ctx context.Context, only []Key) Outcome {
	var out Outcome
	if s.opts.Backend == nil {
		return out
	}
	for _, r := range s.targets(only) {
		k := Key{ID: r.ID, Version: r.Version}
		_, err := s.register(ctx, r)
		switch {
		case err == nil:
			s.forget(k)
			out.Done++
		case Transient(err):
			out.Retry = append(out.Retry, k)
		default:
			s.remember(k, err)
			out.Failed = append(out.Failed, Failure{Key: k, Err: err})
		}
	}
	return out
}

// Transient reports whether a refusal can heal with time: the stack
// answered unavailable or deadline exceeded. Any other code, such as
// invalid argument, failed precondition or already exists, stays the
// same on the next try.
func Transient(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded:
		return true
	}
	return false
}

// targets returns the published versions to register: every one, or
// the listed ones.
func (s *Service) targets(only []Key) []record.Record {
	want := map[Key]bool{}
	for _, k := range only {
		want[k] = true
	}
	var out []record.Record
	for _, r := range s.opts.Store.All() {
		if r.State != record.StatePublished {
			continue
		}
		if only != nil && !want[Key{ID: r.ID, Version: r.Version}] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// RegistrationFailure returns the reason the stack gave for a published
// version it refused for good, or the empty string.
func (s *Service) RegistrationFailure(id string, version int32) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures[Key{ID: id, Version: int(version)}]
}

// RetryRegistration registers one published version again, from the
// action of the detail page. A success clears the reason. A refusal of
// any code keeps a reason on the page.
func (s *Service) RetryRegistration(ctx context.Context, id string, version int32) error {
	if s.opts.Backend == nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("service: the registry has no stack"))
	}
	r, err := s.selectVersion(id, int(version), record.StatePublished)
	if err != nil {
		return err
	}
	k := Key{ID: r.ID, Version: r.Version}
	if _, err := s.register(ctx, r); err != nil {
		s.remember(k, err)
		return connect.NewError(connect.CodeOf(err), err)
	}
	s.forget(k)
	return nil
}

// remember keeps the reason of a refusal for the detail page: the
// message of the stack on one line, cut to maxReason bytes.
func (s *Service) remember(k Key, err error) {
	reason := err.Error()
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		reason = cerr.Message()
	}
	reason = strings.Join(strings.Fields(reason), " ")
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[k] = reason
}

// forget clears the reason of a version the stack took.
func (s *Service) forget(k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, k)
}
