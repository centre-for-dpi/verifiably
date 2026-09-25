// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// ErrNoIssuer reports that the issuer-api is not configured.
var ErrNoIssuer = errors.New("waltid: no issuer-api URL")

// ErrNoVerifier reports that the verifier-api is not configured.
var ErrNoVerifier = errors.New("waltid: no verifier-api URL")

// ErrNoWallet reports that the wallet-api is not configured.
var ErrNoWallet = errors.New("waltid: no wallet-api URL")

// Account is one wallet-api account.
type Account struct {
	// Name is the display name.
	Name string `json:"name"`
	// Email is the login name.
	Email string `json:"email"`
	// Password is the login secret.
	Password string `json:"password"`
	// Type is always email for this adapter.
	Type string `json:"type"`
}

// WalletSession is a wallet-api login: a token and the first wallet.
type WalletSession struct {
	// Token is the wallet-api session token.
	Token string
	// WalletID is the wallet the adapter uses.
	WalletID string
}

// loginResponse is the answer of POST /wallet-api/auth/login.
type loginResponse struct {
	Token string `json:"token"`
}

// walletListing is the answer of GET /wallet-api/wallet/accounts/wallets.
type walletListing struct {
	Wallets []struct {
		ID string `json:"id"`
	} `json:"wallets"`
}

// Login registers the account when it is new and then logs in. It
// returns the session token and the first wallet of the account.
func (c *Client) Login(ctx context.Context, acc Account) (WalletSession, error) {
	if c.wallet == nil {
		return WalletSession{}, ErrNoWallet
	}
	acc.Type = "email"
	// A repeated registration fails because the account exists. The
	// login below decides whether the account is usable.
	ignored2 := c.wallet.JSON(ctx, http.MethodPost, "/wallet-api/auth/register", acc, nil)
	_ = ignored2
	var tok loginResponse
	if err := c.wallet.JSON(ctx, http.MethodPost, "/wallet-api/auth/login", acc, &tok); err != nil {
		return WalletSession{}, fmt.Errorf("waltid: wallet login: %w", err)
	}
	if tok.Token == "" {
		return WalletSession{}, errors.New("waltid: the wallet login answer has no token")
	}
	var list walletListing
	err := c.wallet.WithToken(tok.Token).JSON(ctx, http.MethodGet, "/wallet-api/wallet/accounts/wallets", nil, &list)
	if err != nil {
		return WalletSession{}, fmt.Errorf("waltid: list the wallets: %w", err)
	}
	if len(list.Wallets) == 0 {
		return WalletSession{}, errors.New("waltid: the account has no wallet")
	}
	return WalletSession{Token: tok.Token, WalletID: list.Wallets[0].ID}, nil
}

// HeldCredential is one credential in a walt.id wallet.
type HeldCredential struct {
	// ID is the wallet identifier of the credential.
	ID string `json:"id"`
	// Document is the credential as the wallet stores it.
	Document string `json:"document"`
	// Format is the OID4VCI format identifier.
	Format string `json:"format"`
	// AddedOn is the time the wallet received the credential.
	AddedOn string `json:"addedOn"`
	// ParsedDocument holds the decoded claims.
	ParsedDocument json.RawMessage `json:"parsedDocument"`
}

// ListCredentials reads the credentials of one wallet.
func (c *Client) ListCredentials(ctx context.Context, s WalletSession) ([]HeldCredential, error) {
	if c.wallet == nil {
		return nil, ErrNoWallet
	}
	var out []HeldCredential
	path := fmt.Sprintf("/wallet-api/wallet/%s/credentials", url.PathEscape(s.WalletID))
	if err := c.wallet.WithToken(s.Token).JSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteCredential removes one credential from the wallet for good.
func (c *Client) DeleteCredential(ctx context.Context, s WalletSession, id string) error {
	if c.wallet == nil {
		return ErrNoWallet
	}
	path := fmt.Sprintf("/wallet-api/wallet/%s/credentials/%s?permanent=true",
		url.PathEscape(s.WalletID), url.PathEscape(id))
	_, err := c.wallet.WithToken(s.Token).Do(ctx, dpgclient.Request{Method: http.MethodDelete, Path: path})
	return err
}

// ResolveOffer asks the wallet to read one credential offer. walt.id
// takes the offer URI as a plain text body.
func (c *Client) ResolveOffer(ctx context.Context, s WalletSession, offerURI string) (json.RawMessage, error) {
	if c.wallet == nil {
		return nil, ErrNoWallet
	}
	path := fmt.Sprintf("/wallet-api/wallet/%s/exchange/resolveCredentialOffer", url.PathEscape(s.WalletID))
	resp, err := c.wallet.WithToken(s.Token).Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: path, Body: []byte(offerURI), ContentType: "text/plain",
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// AcceptOffer claims one credential offer into the wallet. pin is the
// transaction code of the offer, or "".
func (c *Client) AcceptOffer(ctx context.Context, s WalletSession, offerURI, pin string) error {
	if c.wallet == nil {
		return ErrNoWallet
	}
	q := url.Values{"requireUserInput": {"false"}}
	if pin != "" {
		q.Set("pinOrTxCode", pin)
	}
	path := fmt.Sprintf("/wallet-api/wallet/%s/exchange/useOfferRequest?%s",
		url.PathEscape(s.WalletID), q.Encode())
	_, err := c.wallet.WithToken(s.Token).Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: path, Body: []byte(offerURI), ContentType: "text/plain",
	})
	return err
}

// PresentResult is the answer of the wallet after a presentation.
type PresentResult struct {
	// RedirectURI is the address the verifier returned.
	RedirectURI string `json:"redirectUri"`
}

// Present answers one OID4VP request from the wallet. The disclosures
// map names the claims to reveal per credential. An empty map reveals
// every claim the request asks for.
func (c *Client) Present(ctx context.Context, s WalletSession, requestURI string,
	credentialIDs []string, disclosures map[string][]string,
) (PresentResult, error) {
	if c.wallet == nil {
		return PresentResult{}, ErrNoWallet
	}
	body := map[string]any{
		"presentationRequest": requestURI,
		"selectedCredentials": credentialIDs,
	}
	if len(disclosures) > 0 {
		body["disclosures"] = disclosures
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return PresentResult{}, fmt.Errorf("waltid: encode the presentation: %w", err)
	}
	path := fmt.Sprintf("/wallet-api/wallet/%s/exchange/usePresentationRequest", url.PathEscape(s.WalletID))
	resp, err := c.wallet.WithToken(s.Token).Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: path, Body: raw, ContentType: "application/json",
	})
	if err != nil {
		return PresentResult{}, err
	}
	var out PresentResult
	if len(strings.TrimSpace(string(resp.Body))) > 0 {
		ignored := json.Unmarshal(resp.Body, &out)
		_ = ignored
	}
	return out, nil
}
