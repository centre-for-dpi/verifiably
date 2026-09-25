// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The key management endpoints of Inji Certify 0.14.0. They wrap the
// MOSIP key manager. The stack keeps every private key (ADR-001
// decision 3).
//
//   - GET /v1/certify/system-info/certificate returns the certificate of
//     a key. The key manager makes the key when it has none.
//   - POST /v1/certify/system-info/uploadCertificate puts a CA signed
//     certificate on a key. The certificate must hold that key.
//   - POST /v1/certify/system-info/upload-ca-certificate adds a CA
//     certificate to the trust store of the stack.
const (
	certificatePath       = "/v1/certify/system-info/certificate"
	uploadCertificatePath = "/v1/certify/system-info/uploadCertificate"
	uploadCAPath          = "/v1/certify/system-info/upload-ca-certificate"
)

// KeyRef names one key of the key manager.
type KeyRef struct {
	// AppID is the application id, such as CERTIFY_VC_SIGN_ED25519.
	AppID string `json:"applicationId"`
	// RefID is the reference id, such as ED25519_SIGN. RSA keys have none.
	RefID string `json:"referenceId"`
}

// KeyTypes maps each key type of the contract onto the key the key
// alias mapper of the stack names for it.
var KeyTypes = []struct {
	Type string
	Ref  KeyRef
}{
	{"Ed25519", KeyRef{AppID: "CERTIFY_VC_SIGN_ED25519", RefID: "ED25519_SIGN"}},
	{"secp256r1", KeyRef{AppID: "CERTIFY_VC_SIGN_EC_R1", RefID: "EC_SECP256R1_SIGN"}},
	{"secp256k1", KeyRef{AppID: "CERTIFY_VC_SIGN_EC_K1", RefID: "EC_SECP256K1_SIGN"}},
	{"RSA", KeyRef{AppID: "CERTIFY_VC_SIGN_RSA"}},
}

// KeyRefOf returns the key of a key type.
func KeyRefOf(keyType string) (KeyRef, bool) {
	for _, k := range KeyTypes {
		if k.Type == keyType {
			return k.Ref, true
		}
	}
	return KeyRef{}, false
}

// KeyTypeOf returns the key type of a key, or "".
func KeyTypeOf(ref KeyRef) string {
	for _, k := range KeyTypes {
		if k.Ref == ref {
			return k.Type
		}
	}
	return ""
}

// KeyCertificate is the certificate of one key.
type KeyCertificate struct {
	// Certificate is the PEM of the certificate.
	Certificate string `json:"certificate"`
}

// wrapped is the response wrapper of the key management endpoints.
type wrapped struct {
	Response json.RawMessage `json:"response"`
	Errors   []struct {
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
		Message      string `json:"message"`
	} `json:"errors"`
}

// unwrap returns the response of a wrapper, or its first error.
func unwrap(body []byte, out any) error {
	var w wrapped
	if err := json.Unmarshal(body, &w); err != nil {
		return fmt.Errorf("inji: read the key manager answer: %w", err)
	}
	if len(w.Errors) > 0 {
		e := w.Errors[0]
		text := e.ErrorMessage
		if text == "" {
			text = e.Message
		}
		return &APIError{Code: e.ErrorCode, Message: text}
	}
	if len(w.Response) == 0 || string(w.Response) == "null" {
		return errors.New("inji: the key manager answer is empty")
	}
	return json.Unmarshal(w.Response, out)
}

// requestTimeLayout is the time layout of a MOSIP request wrapper.
const requestTimeLayout = "2006-01-02T15:04:05.000Z"

// wrap builds the request wrapper of the key management endpoints. It
// names the time both ways the MOSIP wrappers read it.
func wrap(request any, now time.Time) map[string]any {
	at := now.UTC().Format(requestTimeLayout)
	return map[string]any{"id": "string", "version": "string", "requesttime": at, "requestTime": at,
		"metadata": map[string]any{}, "request": request}
}

// Certificate returns the certificate of a key. The key manager makes
// the key when it has none.
func (c *Certify) Certificate(ctx context.Context, ref KeyRef) (KeyCertificate, error) {
	if c == nil {
		return KeyCertificate{}, ErrNoCertify
	}
	q := url.Values{"applicationId": {ref.AppID}}
	if ref.RefID != "" {
		q.Set("referenceId", ref.RefID)
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{Method: http.MethodGet, Path: certificatePath + "?" + q.Encode(), Accept: "application/json"})
	if err != nil {
		return KeyCertificate{}, err
	}
	var out KeyCertificate
	if err := unwrap(resp.Body, &out); err != nil {
		return KeyCertificate{}, err
	}
	if out.Certificate == "" {
		return KeyCertificate{}, errors.New("inji: the key manager returned no certificate")
	}
	return out, nil
}

// UploadCertificate puts a CA signed certificate on a key.
func (c *Certify) UploadCertificate(ctx context.Context, ref KeyRef, certificate string, now time.Time) error {
	return c.post(ctx, uploadCertificatePath, map[string]any{
		"applicationId": ref.AppID, "referenceId": ref.RefID, "certificateData": certificate,
	}, now)
}

// UploadCACertificate adds a CA certificate to the trust store of the
// stack, in a partner domain.
func (c *Certify) UploadCACertificate(ctx context.Context, certificate, domain string, now time.Time) error {
	return c.post(ctx, uploadCAPath, map[string]any{"certificateData": certificate, "partnerDomain": domain}, now)
}

// post sends one wrapped request and reads its status.
func (c *Certify) post(ctx context.Context, path string, request any, now time.Time) error {
	if c == nil {
		return ErrNoCertify
	}
	raw, err := json.Marshal(wrap(request, now))
	if err != nil {
		return fmt.Errorf("inji: encode the key manager request: %w", err)
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: path, Body: raw, ContentType: "application/json", Accept: "application/json",
	})
	if err != nil {
		return err
	}
	var out struct {
		Status string `json:"status"`
	}
	return unwrap(resp.Body, &out)
}
