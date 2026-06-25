package credebl

import (
	"encoding/json"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/vp"
)

// normalizeCredeblCredentials turns CREDEBL's vp_token into the shared
// NormalizedCredential shape. The vp_token is either a DCQL object
// {"credentials":{"vc-1":"<compact-sd-jwt>", ...}} (Credo ≥ 0.5) or a bare
// compact SD-JWT string (older Credo). CREDEBL verifies the KB-JWT holder
// binding but does not surface the holder id, so HolderBinding is Confirmed
// without an identifier.
func normalizeCredeblCredentials(vpToken string) ([]backend.NormalizedCredential, *backend.HolderBinding) {
	vpToken = strings.TrimSpace(vpToken)
	if vpToken == "" {
		return nil, nil
	}
	var creds []backend.NormalizedCredential
	add := func(tok string) {
		if strings.Contains(tok, "~") {
			if nc, ok := vp.FromCompactSDJWT(tok); ok {
				creds = append(creds, nc)
			}
		}
	}
	// DCQL object shape.
	var obj map[string]any
	if json.Unmarshal([]byte(vpToken), &obj) == nil {
		if credsMap, ok := obj["credentials"].(map[string]any); ok {
			for _, v := range credsMap {
				if s, ok := v.(string); ok {
					add(s)
				}
			}
		}
	}
	// Bare quoted JSON string.
	if len(creds) == 0 {
		var s string
		if json.Unmarshal([]byte(vpToken), &s) == nil && s != "" {
			add(s)
		}
	}
	// Raw compact token.
	if len(creds) == 0 {
		add(vpToken)
	}
	if len(creds) == 0 {
		return nil, nil
	}
	return creds, &backend.HolderBinding{Confirmed: true}
}
