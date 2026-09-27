// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The X.509 certificates of an organisation (P6-C9, ADR-068). The agent
// of the organisation keeps the key of each certificate. The platform
// signs a credential template with the signer option X509_P256 or
// X509_ED25519 with the active certificate of the key type. The sources
// are the x509 controller, its service and its repository of the
// release line the stack file runs, read on 2026-09-27:
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/x509/x509.controller.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/x509/src/x509.service.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/x509/src/repositories/x509.repository.ts

// The key types and the states of a certificate (libs/enum/src/enum.ts).
const (
	X509KeyP256    = "P-256"
	X509KeyEd25519 = "Ed25519"
	X509Active     = "Active"
	X509Pending    = "Pending activation"
	X509Inactive   = "In Active"
)

// ErrNoCertificate reports a certificate id that the organisation does
// not hold.
var ErrNoCertificate = errors.New("credebl: the organisation holds no certificate with that id")

// X509Certificate is one certificate row of an organisation.
type X509Certificate struct {
	// ID is the id of the row.
	ID string `json:"id"`
	// KeyType is X509KeyP256 or X509KeyEd25519.
	KeyType string `json:"keyType"`
	// Status is X509Active, X509Pending or X509Inactive.
	Status string `json:"status"`
	// ValidFrom and Expiry bound the validity.
	ValidFrom time.Time `json:"validFrom"`
	Expiry    time.Time `json:"expiry"`
	// CertificateBase64 is the certificate as base64 DER, as the x5c
	// header carries it.
	CertificateBase64 string `json:"certificateBase64"`
}

// X509Certificate reads one certificate of an organisation.
func (c *Client) X509Certificate(ctx context.Context, orgID, id string) (X509Certificate, error) {
	if c == nil {
		return X509Certificate{}, ErrNoPlatform
	}
	var out envelope[X509Certificate]
	if err := c.call(ctx, http.MethodGet, "/v1/x509/"+url.PathEscape(orgID)+"/"+url.PathEscape(id), nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return X509Certificate{}, ErrNoCertificate
		}
		return X509Certificate{}, err
	}
	return out.Data, nil
}

// x509PageSize is the largest page the platform serves.
const x509PageSize = 100

// X509Certificates lists the certificates of an organisation with one
// status and one key type, page by page.
func (c *Client) X509Certificates(ctx context.Context, orgID, status, keyType string) ([]X509Certificate, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	var all []X509Certificate
	for n := 1; ; n++ {
		query := url.Values{"status": {status}, "keyType": {keyType}, "pageNumber": {strconv.Itoa(n)}, "pageSize": {strconv.Itoa(x509PageSize)}}
		var out envelope[struct {
			Data  []X509Certificate `json:"data"`
			Total int               `json:"total"`
		}]
		if err := c.call(ctx, http.MethodGet, "/v1/x509/"+url.PathEscape(orgID)+"?"+query.Encode(), nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Data.Data...)
		if len(out.Data.Data) < x509PageSize || len(all) >= out.Data.Total {
			return all, nil
		}
	}
}

// ActivateX509 makes one certificate the active certificate of its key
// type. The platform answers conflict while another active certificate
// of the key type covers the same dates.
func (c *Client) ActivateX509(ctx context.Context, orgID, id string) (X509Certificate, error) {
	return c.setX509(ctx, orgID, "activate", id)
}

// DeactivateX509 takes one certificate out of use.
func (c *Client) DeactivateX509(ctx context.Context, orgID, id string) (X509Certificate, error) {
	return c.setX509(ctx, orgID, "deactivate", id)
}

// setX509 changes the status of one certificate.
func (c *Client) setX509(ctx context.Context, orgID, action, id string) (X509Certificate, error) {
	if c == nil {
		return X509Certificate{}, ErrNoPlatform
	}
	var out envelope[X509Certificate]
	path := "/v1/x509/" + url.PathEscape(orgID) + "/" + action + "/" + url.PathEscape(id)
	if err := c.call(ctx, http.MethodPut, path, nil, &out); err != nil {
		return X509Certificate{}, err
	}
	return out.Data, nil
}
