// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/static"
)

// The browser store claims and presents with the holder key of the
// browser (ADR-073). wallet.js calls these three JSON endpoints. The
// portal runs the protocol, and the browser signs.
//
//	POST /claim/proof     the proof of a claim, to sign
//	POST /claim/finish    the signed proof; answers the credential
//	POST /present/binding the key binding JWT of an answer, to sign

// claimProof starts a claim into the browser store and answers the
// signing input of the proof.
func (p *Portal) claimProof(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	step, err := p.opts.Service.ClaimStart(r.Context(),
		r.PostFormValue("offer_id"), r.PostFormValue("pin"), r.PostFormValue("jwk"))
	if err != nil {
		return writeJSONError(w, err)
	}
	return writeJSON(w, http.StatusOK, map[string]string{"claim": step.ID, "signing_input": step.SigningInput})
}

// claimFinish sends the signed proof and answers the credential, which
// the browser seals into its store.
func (p *Portal) claimFinish(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	got, err := p.opts.Service.ClaimFinish(r.Context(), r.PostFormValue("claim"), r.PostFormValue("signature"))
	if err != nil {
		return writeJSONError(w, err)
	}
	return writeJSON(w, http.StatusOK, map[string]string{"id": got.ID, "credential": got.Credential, "next": p.opts.Prefix + "/"})
}

// presentBinding answers the signing input of the key binding JWT that
// the chosen credential of a consent form needs. The input is empty for
// a credential with no holder key.
func (p *Portal) presentBinding(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	input, err := p.opts.Service.BindingInput(r.Context(), consentOf(r))
	if err != nil {
		return writeJSONError(w, err)
	}
	return writeJSON(w, http.StatusOK, map[string]string{"signing_input": input})
}

// writeJSON writes one JSON answer.
func writeJSON(w http.ResponseWriter, status int, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, err = w.Write(raw)
	return err
}

// writeJSONError answers a failed step with its sentence. A fault of the
// request is 400, and a fault of the issuer or the wallet 502.
func writeJSONError(w http.ResponseWriter, err error) error {
	status := http.StatusBadGateway
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		switch cerr.Code() {
		case connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeNotFound, connect.CodeDeadlineExceeded:
			status = http.StatusBadRequest
		case connect.CodeUnauthenticated:
			status = http.StatusUnauthorized
		}
	}
	return writeJSON(w, status, map[string]string{"error": message(err)})
}

// consentOf reads the consent form of a request: the chosen card and the
// ticked claims per query, and the key binding the browser signed.
func consentOf(r *http.Request) *walletportalv1.PresentConfirmRequest {
	req := &walletportalv1.PresentConfirmRequest{
		PresentationId: r.PostFormValue("id"),
		SelectedCards:  map[string]string{},
		Disclosed:      map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{},
		KeyBinding:     strings.TrimSpace(r.PostFormValue("key_binding")),
	}
	for name, values := range r.PostForm {
		if len(values) == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(name, "card."):
			req.SelectedCards[strings.TrimPrefix(name, "card.")] = values[0]
		case strings.HasPrefix(name, "claim."):
			req.Disclosed[strings.TrimPrefix(name, "claim.")] =
				&walletportalv1.PresentConfirmRequest_ClaimPaths{Paths: unique(values)}
		}
	}
	return req
}

// signingScript is the status line and the script that signs with the
// holder key of the browser (ADR-073).
func (p *Portal) signingScript(b *pen) template.HTML {
	return b.raw(`<p id="wallet-status" role="status"></p>` +
		`<script src="` + template.HTMLEscapeString(p.opts.Prefix+static.Path) + `" defer></script>`)
}
