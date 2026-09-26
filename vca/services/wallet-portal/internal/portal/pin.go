// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"errors"
	"html/template"
	"net/http"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The PIN step of a stack wallet (P6-I7c). The stack wallet of Inji
// keeps a PIN of six digits. The holder sets it here on first use and
// enters it in each session. Inji Web asks for the same PIN, so the
// holder controls it, and the service keeps it nowhere.
//
//	GET  /pin   the step: a new PIN, the PIN, or the lock
//	POST /pin   pass the PIN to the stack wallet

// pinGate reports whether the own stack keeps a PIN.
func (p *Portal) pinGate(b *pen) bool {
	return !p.opts.Service.BrowserStorage() && b.frame.Has(backendv1.Feature_FEATURE_WALLET_PIN)
}

// pinShut reports a lock state that hides the stack list.
func pinShut(state backendv1.WalletLock) bool {
	switch state {
	case backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN, backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN,
		backendv1.WalletLock_WALLET_LOCK_LOCKED_OUT:
		return true
	}
	return false
}

// pinCard renders the card of the home page that sends the holder to
// the PIN step, or names the lock.
func (p *Portal) pinCard(b *pen, state backendv1.WalletLock) template.HTML {
	name, _ := stackPage(b)
	card := components.Card{ID: "wallet-pin"}
	switch state {
	case backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN:
		card.Title, card.Text = msg.T("holder.pin.new.title", name), msg.T("holder.pin.new.card")
		card.Body = b.part("button", components.Button{Text: msg.T("holder.pin.new.label"), Href: p.opts.Prefix + "/pin", Variant: "primary"})
	case backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN:
		card.Title, card.Text = msg.T("holder.pin.enter.title", name), msg.T("holder.pin.enter.card")
		card.Body = b.part("button", components.Button{Text: msg.T("holder.pin.enter.label"), Href: p.opts.Prefix + "/pin", Variant: "primary"})
	default:
		card.Title, card.Text = msg.T("holder.pin.locked.title", name), msg.T("holder.pin.locked.text")
	}
	return b.part("card", card)
}

// pinPage renders the PIN step.
func (p *Portal) pinPage(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	if !p.pinGate(b) {
		http.NotFound(w, r)
		return nil
	}
	state, err := p.opts.Service.WalletLock(r.Context())
	if err != nil {
		return p.problem(w, r, msg.T("holder.pin.page.label"), msg.T("holder.problem.title"), message(err))
	}
	if !pinShut(state) {
		http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
		return nil
	}
	return p.pinForm(w, r, b, state, "", "")
}

// pinForm draws the step for one lock state, with the error of the last
// attempt beside the field.
func (p *Portal) pinForm(w http.ResponseWriter, r *http.Request, b *pen, state backendv1.WalletLock, problem, confirmProblem string) error {
	name, _ := stackPage(b)
	pinField := func(id, label, hint, autocomplete, fieldErr string) template.HTML {
		return b.part("field", components.Field{
			ID: id, Label: label, Type: "password", Hint: hint, Error: fieldErr, Required: true, Autocomplete: autocomplete,
			Attrs: map[string]string{"inputmode": "numeric", "pattern": "[0-9]{6}", "minlength": "6", "maxlength": "6"},
		})
	}
	var content template.HTML
	title, lead := msg.T("holder.pin.enter.page.label"), msg.T("holder.pin.enter.lead", name)
	switch state {
	case backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN:
		title, lead = msg.T("holder.pin.new.page.label"), msg.T("holder.pin.new.lead", name)
		content = b.form(p.opts.Prefix+"/pin", nil,
			components.Button{Text: msg.T("holder.pin.new.submit.label"), Type: "submit", Variant: "primary"},
			pinField("pin", msg.T("holder.pin.field.new.label"), msg.T("holder.pin.field.new.hint"), "new-password", problem),
			pinField("pin_confirm", msg.T("holder.pin.field.again.label"), msg.T("holder.pin.field.again.hint"), "new-password", confirmProblem))
	case backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN:
		content = b.form(p.opts.Prefix+"/pin", nil,
			components.Button{Text: msg.T("holder.pin.enter.submit.label"), Type: "submit", Variant: "primary"},
			pinField("pin", msg.T("holder.pin.field.label"), msg.T("holder.pin.field.hint", name), "current-password", problem))
	default:
		title, lead = msg.T("holder.pin.locked.page.label"), msg.T("holder.pin.locked.title", name)
		content = b.part("card", components.Card{ID: "pin-locked", Title: msg.T("holder.pin.locked.title", name), Text: msg.T("holder.pin.locked.text")})
	}
	card := b.part("card", components.Card{ID: "pin-step", Title: msg.T("holder.pin.card.title"), Text: msg.T("holder.pin.control"), Body: content})
	if state == backendv1.WalletLock_WALLET_LOCK_LOCKED_OUT {
		card = content
	}
	return p.render(w, r, b, components.Page{Title: title, Lead: lead, Description: lead, Content: card})
}

// pinSubmit passes the PIN to the stack wallet and returns to the home
// page. A refused PIN draws the step again with the reason.
func (p *Portal) pinSubmit(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	b := p.pen(r)
	if !p.pinGate(b) {
		http.NotFound(w, r)
		return nil
	}
	// The state of the stack says whether this is the first use, which
	// takes the PIN twice.
	state, err := p.opts.Service.WalletLock(r.Context())
	if err != nil {
		return p.problem(w, r, msg.T("holder.pin.page.label"), msg.T("holder.problem.title"), message(err))
	}
	first := state == backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN
	err = p.opts.Service.Unlock(r.Context(), r.PostFormValue("pin"), r.PostFormValue("pin_confirm"), first)
	if err == nil {
		http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
		return nil
	}
	if now, lerr := p.opts.Service.WalletLock(r.Context()); lerr == nil && pinShut(now) {
		state = now
	}
	pinErr, confirmErr := message(err), ""
	if errors.Is(err, service.ErrPinMismatch) {
		pinErr, confirmErr = "", pinErr
	}
	return p.pinForm(w, r, b, state, pinErr, confirmErr)
}
