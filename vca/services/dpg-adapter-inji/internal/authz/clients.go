// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Client is one wallet client of the server. A client without a key is
// a public client: PKCE alone guards its code. A client with a key must
// sign a client assertion at the token endpoint (private_key_jwt,
// RFC 7523 section 2.2). Inji Web is such a client: Mimoto signs with
// the key of its key store.
type Client struct {
	// ID is the client_id.
	ID string `json:"client_id"`
	// RedirectURIs are the redirect URIs. A request must name one of
	// them exactly (RFC 9700 section 2.1).
	RedirectURIs []string `json:"redirect_uris"`
	// JWK is the public key of the client assertion, when the client has
	// one.
	JWK json.RawMessage `json:"jwk,omitempty"`
}

// ParseClients reads the client list of VCA_INJI_WALLET_CLIENTS: a JSON
// array of clients. Empty means none.
func ParseClients(raw string) ([]Client, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []Client
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("authz: read the wallet clients: %w", err)
	}
	return out, nil
}

// validate checks one client: an id, absolute redirect URIs without a
// fragment, and a public signing key when it names one.
func (c Client) validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("authz: a wallet client has no client_id")
	}
	if len(c.RedirectURIs) == 0 {
		return fmt.Errorf("authz: the wallet client %s has no redirect URI", c.ID)
	}
	for _, r := range c.RedirectURIs {
		u, err := url.Parse(r)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
			return fmt.Errorf("authz: the redirect URI %q of %s is not an absolute URL without a fragment", r, c.ID)
		}
	}
	if len(c.JWK) == 0 {
		return nil
	}
	if _, err := c.key(); err != nil {
		return fmt.Errorf("authz: the key of %s: %w", c.ID, err)
	}
	return nil
}

// key returns the public key of the client assertion.
func (c Client) key() (jose.JWK, error) {
	k, err := jose.ParseJWK(c.JWK)
	if err != nil {
		return jose.JWK{}, err
	}
	if !k.IsPublic() {
		return jose.JWK{}, errors.New("the key is not a public key")
	}
	if rsaKey, isRSA := k.Key.(*rsa.PublicKey); isRSA && rsaKey.N.BitLen() < jose.MinRSABits {
		return jose.JWK{}, fmt.Errorf("the RSA key has %d bits, fewer than %d", rsaKey.N.BitLen(), jose.MinRSABits)
	}
	return k, nil
}

// allows reports whether the redirect URI is one of the client, by exact
// string comparison.
func (c Client) allows(redirect string) bool {
	for _, r := range c.RedirectURIs {
		if r == redirect {
			return true
		}
	}
	return false
}
