// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// injiRotatePath is the rotation of the token key of the holder
// authorization server on the Inji adapter. The adapter serves it on its
// host port; the proxy of the pair does not publish it (ADR-056
// decision 6).
const injiRotatePath = "/internal/authz/rotate-key"

// injiRotationLabel is the message of the rotation token. The adapter
// derives the same token (authz.RotationToken).
const injiRotationLabel = "vca inji authz key rotation"

// RotateOptions holds one run of vca dpg rotate-authz-key.
type RotateOptions struct {
	BootstrapOptions
	// Immediate signs with the new key at once and drops the old key
	// from the key set, for a compromised key.
	Immediate bool
}

// RotateResult is the answer of the adapter.
type RotateResult struct {
	// Kid is the kid of the new key.
	Kid string `json:"kid"`
	// ActiveFrom is when the new key starts to sign.
	ActiveFrom time.Time `json:"active_from"`
	// Retiring lists the old keys by kid with the time they leave the
	// key set.
	Retiring map[string]time.Time `json:"retiring"`
}

// injiRotationToken returns the rotation token of a pair session key:
// the HMAC-SHA256 of a fixed label, in hex.
func injiRotationToken(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(injiRotationLabel))
	return hex.EncodeToString(mac.Sum(nil))
}

// RotateAuthzKey asks the Inji adapter of the pair to rotate the token
// key of its holder authorization server (ADR-056 decision 6). The run
// proves that it holds the pair session key with the rotation token.
func RotateAuthzKey(ctx context.Context, opts RotateOptions) (RotateResult, error) {
	if opts.Pair.Dpg != configv1.Dpg_DPG_INJI {
		return RotateResult{}, fmt.Errorf("rotate-authz-key: only the Inji stack runs a holder authorization server, not %s",
			ShortName(opts.Pair.Dpg.String()))
	}
	secret := opts.value("VCA_INJI_AUTHZ_KEY_SECRET", opts.Values["VCA_SECRETS_SESSION_KEY"])
	if secret == "" {
		return RotateResult{}, errors.New("rotate-authz-key: the .env of the issuer pair holds no VCA_INJI_AUTHZ_KEY_SECRET; run vca setup first")
	}
	base, err := opts.adapterURL()
	if err != nil {
		return RotateResult{}, err
	}
	target := base + injiRotatePath
	if opts.Immediate {
		target += "?immediate=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return RotateResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+injiRotationToken(secret))
	res, err := opts.client().Do(req)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate-authz-key: the adapter at %s: %w", base, err)
	}
	defer func() { anyval.Discard(res.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate-authz-key: read the answer: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return RotateResult{}, fmt.Errorf("rotate-authz-key: the adapter answered %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var out RotateResult
	if err := json.Unmarshal(body, &out); err != nil {
		return RotateResult{}, fmt.Errorf("rotate-authz-key: read the answer: %w", err)
	}
	var r BootstrapResult
	r.step(opts.Out, "The new token key %s signs from %s.", out.Kid, out.ActiveFrom.UTC().Format(time.RFC3339))
	for kid, at := range out.Retiring {
		r.step(opts.Out, "The old token key %s leaves the key set at %s.", kid, at.UTC().Format(time.RFC3339))
	}
	return out, nil
}
