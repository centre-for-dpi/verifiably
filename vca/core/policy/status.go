// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/delegation"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
)

// FailOpen keeps an unreachable status list out of the verdict.
const FailOpen = "open"

// FailClosed makes an unreachable status list fail the check.
const FailClosed = "closed"

// ParamFailMode is the name of the fail mode parameter.
const ParamFailMode = "fail_mode"

// status checks every credential against its status list
// (ADR-024 decision 3). The verifier chooses the fail mode.
func status(ctx context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameStatus)
	}
	closed := failClosed(pc.Param(ParamFailMode, FailClosed))
	out := make([]CheckResult, 0, len(p.Credentials))
	for i, c := range p.Credentials {
		out = append(out, statusOf(ctx, i, c, pc, closed))
	}
	return out
}

// failClosed reports whether an unreachable list fails the check. The
// value accepts closed, fail-closed, open, and fail-open.
func failClosed(mode string) bool {
	return !strings.HasSuffix(strings.ToLower(strings.TrimSpace(mode)), FailOpen)
}

func statusOf(ctx context.Context, index int, c Credential, pc Context, closed bool) CheckResult {
	ref, ok := delegation.StatusRefOf(c.VC)
	if !ok || ref.URI == "" {
		return result(NameStatus, Skip, index, "the credential declares no status list", nil)
	}
	ev := map[string]string{"list": ref.URI, "index": strconv.FormatInt(ref.Index, 10), "purpose": ref.Purpose}
	unreachable := func(detail string) CheckResult {
		if closed {
			return result(NameStatus, Fail, index, detail, ev)
		}
		return result(NameStatus, Error, index, detail, ev)
	}
	if pc.Status == nil {
		return unreachable("the service has no status list fetcher")
	}
	raw, err := pc.Status(ctx, ref.URI)
	if errors.Is(err, ErrStale) {
		return result(NameStatus, Fail, index, staleStatusDetail, stale(ev))
	}
	if err != nil {
		return unreachable("the status list is not reachable")
	}
	value, signed, err := statusValue(ctx, ref, raw, pc)
	ev["signature"] = signed
	if err != nil {
		return unreachable(err.Error())
	}
	if value != 0 {
		ev["value"] = strconv.FormatUint(uint64(value), 10)
		return result(NameStatus, Fail, index, "the issuer set the status of the credential", ev)
	}
	return result(NameStatus, Pass, index, "the issuer did not set the status of the credential", ev)
}

// statusValue reads the status of one entry from a list document. It
// returns the value and how the document was secured.
func statusValue(ctx context.Context, ref delegation.StatusRef, raw []byte, pc Context) (uint8, string, error) {
	claims, signed, err := statusClaims(ctx, raw, ref.Issuer, pc)
	if err != nil {
		return 0, signed, err
	}
	if strings.Contains(strings.ToLower(ref.Type), "bitstring") {
		_, list, perr := bitstring.ParseCredential(claims)
		if perr != nil {
			return 0, signed, errors.New("the status list credential does not parse")
		}
		set, gerr := list.Get(int(ref.Index))
		if gerr != nil {
			return 0, signed, errors.New("the status list is too short for the index")
		}
		if set {
			return 1, signed, nil
		}
		return 0, signed, nil
	}
	_, list, perr := token.ParseJWTClaims(claims)
	if perr != nil {
		return 0, signed, errors.New("the status list token does not parse")
	}
	value, gerr := list.Get(int(ref.Index))
	if gerr != nil {
		return 0, signed, errors.New("the status list is too short for the index")
	}
	return value, signed, nil
}

// statusClaims decodes the list document. A JSON object is read as it
// is. A compact JWS is checked with the issuer keys when the service
// has a key resolver.
func statusClaims(ctx context.Context, raw []byte, issuer string, pc Context) (map[string]any, string, error) {
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, "not checked", errors.New("the status list document does not parse")
		}
		return doc, "not checked", nil
	}
	compact := strings.TrimSpace(string(raw))
	signed := "not checked"
	if pc.Keys != nil {
		hdr, err := jose.PeekHeader(compact)
		if err != nil {
			return nil, signed, errors.New("the status list token does not parse")
		}
		set, err := pc.Keys(ctx, issuer, hdr.Kid)
		if err != nil {
			return nil, signed, errors.New("the status list keys are not available")
		}
		if _, _, err := jose.VerifyWithJWKS(compact, set, jose.SigningAlgorithms); err != nil {
			return nil, signed, errors.New("the status list signature is not valid")
		}
		signed = "valid"
	}
	payload, err := jose.PeekPayload(compact)
	if err != nil {
		return nil, signed, errors.New("the status list token does not parse")
	}
	return payload, signed, nil
}
