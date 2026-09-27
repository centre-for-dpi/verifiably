// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/holderkey"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// errNoBinding refuses a bound credential with no key binding JWT.
var errNoBinding = connect.NewError(connect.CodeFailedPrecondition, errors.New(
	"this credential is bound to the key of your browser; turn on JavaScript so the browser signs the answer"))

// BindingInput returns the signing input of the key binding JWT that the
// chosen credential of the browser store needs (ADR-073). It returns an
// empty text for a credential that names no holder key, which the
// wallet presents as it is.
func (s *Service) BindingInput(ctx context.Context, req *walletportalv1.PresentConfirmRequest) (string, error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return "", err
	}
	_, parsed, rec, err := s.request(ctx, citizen, req.GetPresentationId())
	if err != nil {
		return "", err
	}
	chosen, disclosed := selections(req)
	if len(chosen) == 0 || rec.Interactive != "" {
		return "", nil
	}
	held, found := s.getHeld(ctx, citizen, chosen[0])
	if !found {
		// A credential of the stack wallet binds itself.
		return "", nil
	}
	token, _, bound, err := disclosedToken(held, disclosed)
	if err != nil || !bound {
		return "", err
	}
	input, err := holderkey.BindingInput(token, parsed.ClientID, parsed.Nonce, s.opts.Now())
	if err != nil {
		return "", connect.NewError(connect.CodeInvalidArgument, err)
	}
	return input, nil
}

// disclosedToken returns the token a held credential presents with the
// disclosed claims, and its holder key when it names one. Only an SD-JWT
// discloses claims and names a key that the browser binds.
func disclosedToken(held record, disclosed []string) (string, jose.JWK, bool, error) {
	if held.Format != commonv1.Format_FORMAT_DC_SD_JWT && held.Format != commonv1.Format_FORMAT_VC_SD_JWT {
		return string(held.Payload), jose.JWK{}, false, nil
	}
	token, err := present.Disclosed(string(held.Payload), disclosed)
	if err != nil {
		return "", jose.JWK{}, false, connect.NewError(connect.CodeInvalidArgument, err)
	}
	key, bound := holderkey.Bound(string(held.Payload))
	return token, key, bound, nil
}

// bind appends the key binding JWT of the browser to a disclosed token,
// once it covers the token and the request.
func bind(token, kb string, key jose.JWK, parsed present.Request) (string, error) {
	if kb == "" {
		return "", errNoBinding
	}
	if err := holderkey.CheckBinding(kb, token, parsed.ClientID, parsed.Nonce, key); err != nil {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("the key binding of the browser does not cover this answer"))
	}
	return token + kb, nil
}

// getHeld returns one credential of the browser store, when it holds it.
func (s *Service) getHeld(ctx context.Context, citizen session.Citizen, id string) (record, bool) {
	rec, err := s.get(ctx, KindHeld, citizen.WalletKey(), id)
	return rec, err == nil
}
