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

// BindingInputs returns the signing input of the holder binding of each
// chosen credential of the browser store that names a holder key, keyed
// by query id: the key binding JWT of an SD-JWT, or the VP JWT around a
// jwt_vc_json credential (ADR-083 decision 5). A credential with no
// holder key, and one of the stack wallet, has no entry.
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
		token, binding, terr := disclosedToken(held, c.paths)
		if terr != nil {
			return nil, terr
		}
		var input string
		var ierr error
		switch binding.kind {
		case bindNone:
			continue
		case bindVP:
			input, ierr = holderkey.VPInput(token, binding.holder, binding.key, parsed.ClientID, parsed.Nonce, s.opts.Now())
		default:
			input, ierr = holderkey.BindingInput(token, parsed.ClientID, parsed.Nonce, s.opts.Now())
		}
		if ierr != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, ierr)
		}
		out[c.query] = input
	}
	return out, nil
}

// The kinds of holder binding of a credential of the browser store.
const (
	// bindNone sends the credential as issued.
	bindNone = iota
	// bindKB appends a key binding JWT to an SD-JWT.
	bindKB
	// bindVP wraps a jwt_vc_json credential in a VP JWT.
	bindVP
)

// holderBinding is how the browser store binds one credential: the kind,
// the holder key, and the holder id a VP JWT names.
type holderBinding struct {
	kind   int
	key    jose.JWK
	holder string
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
// disclosed claims, and how the browser binds it. An SD-JWT discloses
// claims and names the key of a key binding JWT, an mDoc keeps the
// chosen elements, and a jwt_vc_json credential names the key of a VP
// JWT.
func disclosedToken(held record, disclosed []string) (string, holderBinding, error) {
	switch held.Format {
	case commonv1.Format_FORMAT_MSO_MDOC:
		// An mDoc keeps the elements the holder chose; the MSO signs a
		// digest of each, so the issuer signature stays valid.
		token, err := vc.MdocDisclose(held.Payload, func(element string) bool { return chosenElement(element, disclosed) })
		if err != nil {
			return "", holderBinding{}, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return string(token), holderBinding{}, nil
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		token := string(held.Payload)
		key, holder, bound := holderkey.BoundJWT(token)
		if !bound {
			return token, holderBinding{}, nil
		}
		return token, holderBinding{kind: bindVP, key: key, holder: holder}, nil
	case commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_VC_SD_JWT:
		token, err := present.Disclosed(string(held.Payload), disclosed)
		if err != nil {
			return "", holderBinding{}, connect.NewError(connect.CodeInvalidArgument, err)
		}
		key, bound := holderkey.Bound(string(held.Payload))
		if !bound {
			return token, holderBinding{}, nil
		}
		return token, holderBinding{kind: bindKB, key: key}, nil
	}
	return string(held.Payload), holderBinding{}, nil
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

// bind joins the holder binding of the browser to a disclosed token,
// once it covers the token and the request: a key binding JWT after an
// SD-JWT, or the VP JWT that carries a jwt_vc_json credential.
func bind(token, signed string, b holderBinding, parsed present.Request) (string, error) {
	if signed == "" {
		return "", errNoBinding
	}
	if b.kind == bindVP {
		if err := holderkey.CheckVP(signed, token, parsed.ClientID, parsed.Nonce, b.key); err != nil {
			return "", connect.NewError(connect.CodeInvalidArgument, errors.New("the VP JWT of the browser does not cover this answer"))
		}
		return signed, nil
	}
	if err := holderkey.CheckBinding(signed, token, parsed.ClientID, parsed.Nonce, b.key); err != nil {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("the key binding of the browser does not cover this answer"))
	}
	return token + signed, nil
}

// getHeld returns one credential of the browser store, when it holds it.
func (s *Service) getHeld(ctx context.Context, citizen session.Citizen, id string) (record, bool) {
	rec, err := s.get(ctx, KindHeld, citizen.WalletKey(), id)
	return rec, err == nil
}
