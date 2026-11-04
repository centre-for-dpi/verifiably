package handlers

import "github.com/verifiably/verifiably-go/internal/outbound"

// permitting returns a policy that allows exactly the given destinations for
// the two allowlisted purposes.
//
// Tests inject this rather than switching the development mode on, so they
// exercise the allowlist a deployment actually runs under: a test that opted
// out of the check would still pass if the check were deleted.
func permitting(urls ...string) *outbound.Policy {
	return outbound.New(outbound.Config{Allow: map[outbound.Purpose][]string{
		outbound.Verifier:      urls,
		outbound.OperatorFetch: urls,
	}})
}
