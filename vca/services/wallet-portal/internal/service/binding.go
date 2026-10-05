// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/holderkey"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// errNoBinding refuses a bound credential with no key binding JWT.
var errNoBinding = connect.NewError(connect.CodeFailedPrecondition, errors.New(
	"this credential is bound to the key of your browser; turn on JavaScript so the browser signs the answer"))

// BindingInput returns the signing input of the key binding JWT that
// the chosen credential of the browser store needs (ADR-073). It returns
// an empty text for a credential that names no holder key, which the
// wallet presents as it is. An answer with several bound credentials
// takes BindingInputs.
func (s *Service) BindingInput(ctx context.Context, req *walletportalv1.PresentConfirmRequest) (string, error) {
	inputs, err := s.BindingInputs(ctx, req)
	if err != nil {
		return "", err
	}
	for _, c := range choices(req) {
		if input, ok := inputs[c.query]; ok {
			return input, nil
		}
	}
	return "", nil
}

// BindingInputs returns the signing input of the key binding JWT of each
// chosen credential of the browser store that names a holder key, keyed
// by query id. A credential with no holder key, and one of the stack
// wallet, has no entry.
func (s *Service) BindingInputs(ctx context.Context, req *walletportalv1.PresentConfirmRequest) (map[string]string, error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	_, parsed, rec, err := s.request(ctx, citizen, req.GetPresentationId())
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if rec.Interactive != "" {
		return out, nil
	}
	for _, c := range choices(req) {
		held, found := s.getHeld(ctx, citizen, c.card)
		if !found {
			// A credential of the stack wallet binds itself.
			continue
		}
		token, _, bound, terr := disclosedToken(held, c.paths)
		if terr != nil {
			return nil, terr
		}
		if !bound {
			continue
		}
		input, ierr := holderkey.BindingInput(token, parsed.ClientID, parsed.Nonce, s.opts.Now())
		if ierr != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, ierr)
		}
		out[c.query] = input
	}
	return out, nil
}

// choice is one chosen credential of an answer: the query it answers,
// the card, and the claim paths the holder agreed to disclose.
type choice struct {
	query string
	card  string
	paths []string
}

// choices returns the chosen credentials of an answer in query id order.
func choices(req *walletportalv1.PresentConfirmRequest) []choice {
	queries := make([]string, 0, len(req.GetSelectedCards()))
	for query := range req.GetSelectedCards() {
		queries = append(queries, query)
	}
	sort.Strings(queries)
	out := make([]choice, 0, len(queries))
	for _, q := range queries {
		out = append(out, choice{query: q, card: req.GetSelectedCards()[q], paths: req.GetDisclosed()[q].GetPaths()})
	}
	return out
}

// keyBindings reads the key binding field of an answer: one JWT for the
// one bound credential, or a JSON object of query id to JWT when the
// answer holds several.
func keyBindings(text string) (map[string]string, string, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "{") {
		return nil, text, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, "", connect.NewError(connect.CodeInvalidArgument, errors.New("the key bindings of the browser are not a JSON object"))
	}
	return out, "", nil
}

// disclosedToken returns the token a held credential presents with the
// disclosed claims, and its holder key when it names one. Only an SD-JWT
// discloses claims and names a key that the browser binds.
func disclosedToken(held record, disclosed []string) (string, jose.JWK, bool, error) {
	if held.Format == commonv1.Format_FORMAT_MSO_MDOC {
		// An mDoc keeps the elements the holder chose; the MSO signs a
		// digest of each, so the issuer signature stays valid.
		token, err := vc.MdocDisclose(held.Payload, func(element string) bool { return chosenElement(element, disclosed) })
		if err != nil {
			return "", jose.JWK{}, false, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return string(token), jose.JWK{}, false, nil
	}
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

// chosenElement reports whether the holder chose an mDoc element, named
// namespace dot identifier. A DCQL path names the namespace of the
// request, which may differ from the namespace of the issuer, so the
// element identifier decides.
func chosenElement(element string, disclosed []string) bool {
	name := element[strings.LastIndex(element, ".")+1:]
	for _, path := range disclosed {
		if path == element || path[strings.LastIndex(path, ".")+1:] == name {
			return true
		}
	}
	return false
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
