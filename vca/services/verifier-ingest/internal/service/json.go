// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/json"
	"fmt"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
)

// unmarshalParams reads the request parameters the decoder wrote.
func unmarshalParams(payload []byte, out *map[string]string) error {
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("service: read the request parameters: %w", err)
	}
	return nil
}

// marshalClaims writes the claims of a request object as JSON.
func marshalClaims(claims map[string]any) ([]byte, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("service: write the request object claims: %w", err)
	}
	return data, nil
}

// checkQuery reads a DCQL query and checks its rules.
func checkQuery(raw string) error {
	_, err := dcql.Parse([]byte(raw))
	return err
}
