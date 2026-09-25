// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The wallet-api of release 0.18.2 manages the keys, the DIDs, the
// pending credentials, and the event log of a wallet:
//
//	GET  /wallet-api/wallet/{wallet}/keys
//	POST /wallet-api/wallet/{wallet}/keys/generate
//	GET  /wallet-api/wallet/{wallet}/dids
//	POST /wallet-api/wallet/{wallet}/dids/create/{method}?keyId=&alias=
//	POST /wallet-api/wallet/{wallet}/dids/default?did=
//	POST /wallet-api/wallet/{wallet}/credentials/{id}/reject
//	GET  /wallet-api/wallet/{wallet}/eventlog

// WalletKey is one entry of GET keys.
type WalletKey struct {
	// Algorithm is the key type, such as Ed25519.
	Algorithm string `json:"algorithm"`
	// CryptoProvider names the key store of the wallet.
	CryptoProvider string `json:"cryptoProvider"`
	// KeyID holds the id of the key.
	KeyID struct {
		ID string `json:"id"`
	} `json:"keyId"`
	// Name is the name of the key, when it has one.
	Name string `json:"name"`
}

// WalletDID is one entry of GET dids.
type WalletDID struct {
	DID       string `json:"did"`
	Alias     string `json:"alias"`
	KeyID     string `json:"keyId"`
	Default   bool   `json:"default"`
	CreatedOn string `json:"createdOn"`
}

// WalletEvent is one entry of the event log.
type WalletEvent struct {
	ID           json.Number     `json:"id"`
	Event        string          `json:"event"`
	Action       string          `json:"action"`
	Timestamp    string          `json:"timestamp"`
	Originator   string          `json:"originator"`
	CredentialID string          `json:"credentialId"`
	Data         json.RawMessage `json:"data"`
}

// Counterpart names the party of an event: the organisation of the event
// data, else the originator.
func (e WalletEvent) Counterpart() string {
	var data struct {
		Organization struct {
			Name string `json:"name"`
		} `json:"organization"`
	}
	if json.Unmarshal(e.Data, &data) == nil && data.Organization.Name != "" {
		return data.Organization.Name
	}
	return e.Originator
}

// Time parses the timestamp of an event, or the zero time.
func (e WalletEvent) Time() time.Time { return parseTime(e.Timestamp) }

// Time parses the creation time of a DID, or the zero time.
func (d WalletDID) Time() time.Time { return parseTime(d.CreatedOn) }

// parseTime reads an RFC 3339 time, or gives the zero time.
func parseTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// walletPath returns a path under the wallet of a session.
func walletPath(s WalletSession, rest string) string {
	return "/wallet-api/wallet/" + url.PathEscape(s.WalletID) + rest
}

// ListKeys reads the keys of a wallet.
func (c *Client) ListKeys(ctx context.Context, s WalletSession) ([]WalletKey, error) {
	if c.wallet == nil {
		return nil, ErrNoWallet
	}
	var out []WalletKey
	if err := c.wallet.WithToken(s.Token).JSON(ctx, http.MethodGet, walletPath(s, "/keys"), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GenerateKey makes a jwk key of one type and returns its id.
func (c *Client) GenerateKey(ctx context.Context, s WalletSession, keyType string) (string, error) {
	if c.wallet == nil {
		return "", ErrNoWallet
	}
	raw, err := json.Marshal(map[string]string{"backend": "jwk", "keyType": keyType})
	if err != nil {
		return "", err
	}
	id, err := c.wallet.WithToken(s.Token).Text(ctx, http.MethodPost, walletPath(s, "/keys/generate"), "application/json", raw)
	if err != nil {
		return "", err
	}
	return strings.Trim(strings.TrimSpace(id), `"`), nil
}

// ListDIDs reads the DIDs of a wallet.
func (c *Client) ListDIDs(ctx context.Context, s WalletSession) ([]WalletDID, error) {
	if c.wallet == nil {
		return nil, ErrNoWallet
	}
	var out []WalletDID
	if err := c.wallet.WithToken(s.Token).JSON(ctx, http.MethodGet, walletPath(s, "/dids"), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateDID makes a DID of a method, such as key, with an existing key
// or a new one, and returns the DID.
func (c *Client) CreateDID(ctx context.Context, s WalletSession, method, keyID, alias string) (string, error) {
	if c.wallet == nil {
		return "", ErrNoWallet
	}
	q := url.Values{}
	if keyID != "" {
		q.Set("keyId", keyID)
	}
	if alias != "" {
		q.Set("alias", alias)
	}
	path := walletPath(s, "/dids/create/"+url.PathEscape(method))
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	did, err := c.wallet.WithToken(s.Token).Text(ctx, http.MethodPost, path, "", nil)
	if err != nil {
		return "", err
	}
	return strings.Trim(strings.TrimSpace(did), `"`), nil
}

// SetDefaultDID picks the DID the wallet binds new credentials to.
func (c *Client) SetDefaultDID(ctx context.Context, s WalletSession, did string) error {
	if c.wallet == nil {
		return ErrNoWallet
	}
	_, err := c.wallet.WithToken(s.Token).Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: walletPath(s, "/dids/default?did="+url.QueryEscape(did)),
	})
	return err
}

// RejectOffer declines an offer. The wallet-api has no decline of an
// offer as such: it takes the offer as pending credentials, which
// requireUserInput asks for, and the adapter then rejects each one with
// the note of the holder. No pending credential reaches the wallet.
func (c *Client) RejectOffer(ctx context.Context, s WalletSession, offerURI, note string) error {
	if c.wallet == nil {
		return ErrNoWallet
	}
	resp, err := c.wallet.WithToken(s.Token).Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: walletPath(s, "/exchange/useOfferRequest?requireUserInput=true"),
		Body: []byte(offerURI), ContentType: "text/plain", Accept: "application/json",
	})
	if err != nil {
		return err
	}
	var pending []HeldCredential
	if err := json.Unmarshal(resp.Body, &pending); err != nil {
		return fmt.Errorf("waltid: read the pending credentials: %w", err)
	}
	for _, p := range pending {
		path := walletPath(s, "/credentials/"+url.PathEscape(p.ID)+"/reject")
		if err := c.wallet.WithToken(s.Token).JSON(ctx, http.MethodPost, path, map[string]string{"note": note}, nil); err != nil {
			return err
		}
	}
	return nil
}

// eventPage is the answer of GET eventlog.
type eventPage struct {
	Items []WalletEvent `json:"items"`
	// NextStartingAfter is the cursor of the next page, or null.
	NextStartingAfter *string `json:"nextStartingAfter"`
	// Reason is the text of a failed filter.
	Reason string `json:"reason"`
}

// ListEvents reads one page of the event log, newest first. after is the
// cursor of walt.id; the answer gives the next one, or "".
func (c *Client) ListEvents(ctx context.Context, s WalletSession, limit int, after string) ([]WalletEvent, string, error) {
	if c.wallet == nil {
		return nil, "", ErrNoWallet
	}
	q := url.Values{"limit": {fmt.Sprint(limit)}, "sortBy": {"timestamp"}, "sortOrder": {"desc"}}
	if after != "" {
		q.Set("startingAfter", after)
	}
	var out eventPage
	if err := c.wallet.WithToken(s.Token).JSON(ctx, http.MethodGet, walletPath(s, "/eventlog?"+q.Encode()), nil, &out); err != nil {
		return nil, "", err
	}
	if out.Reason != "" {
		return nil, "", fmt.Errorf("waltid: the event log answered: %s", out.Reason)
	}
	next := ""
	if out.NextStartingAfter != nil {
		next = *out.NextStartingAfter
	}
	return out.Items, next, nil
}
