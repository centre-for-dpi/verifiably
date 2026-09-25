/* SPDX-License-Identifier: Apache-2.0
   vca UI kit: the Digital Credentials API channel (ADR-043 decisions 1 to 3).

   A page marks a button with data-dcapi-offer, the credential offer URI of
   OpenID for Verifiable Credential Issuance. The button starts hidden. This
   script shows it only when the browser has the Digital Credentials API and
   allows the issuance protocol. A click hands the offer to the wallet of the
   device through navigator.credentials.create, as the W3C Digital
   Credentials draft of 2026 describes. The page keeps the QR code and the
   link for every other browser. The outcome goes to the toast region, in
   the words the page puts in data-dcapi-ok, data-dcapi-cancel and
   data-dcapi-fail.

   The script has no dependency and no build step. It does nothing on a page
   without such a button. */
(function(){
  'use strict';
  var PROTOCOL = 'openid4vci-v1';

  /* supported is the feature test. A browser without the static
     userAgentAllowsProtocol method but with DigitalCredential gets the
     button too, because the draft adds that method late. */
  function supported() {
    var DC = window.DigitalCredential;
    if (typeof DC !== 'function' || !navigator.credentials || typeof navigator.credentials.create !== 'function') {
      return false;
    }
    if (typeof DC.userAgentAllowsProtocol === 'function') {
      try { return DC.userAgentAllowsProtocol(PROTOCOL) === true; } catch (e) { return false; }
    }
    return true;
  }

  /* offerOf reads the credential offer object from an offer URI: by value
     in credential_offer, or by reference in credential_offer_uri, which the
     browser fetches. */
  function offerOf(uri) {
    var query = uri.indexOf('?') >= 0 ? uri.slice(uri.indexOf('?') + 1) : '';
    var params = new URLSearchParams(query);
    var byValue = params.get('credential_offer');
    if (byValue) {
      try { return Promise.resolve(JSON.parse(byValue)); } catch (e) { return Promise.reject(e); }
    }
    var byReference = params.get('credential_offer_uri');
    if (byReference && /^https:\/\//.test(byReference)) {
      return fetch(byReference, { credentials: 'omit', headers: { 'Accept': 'application/json' } })
        .then(function(res){
          if (!res.ok) { throw new Error('offer ' + res.status); }
          return res.json();
        });
    }
    return Promise.reject(new Error('no credential offer'));
  }

  /* toast writes one message into the aria-live region of the layout. */
  function toast(level, text) {
    var region = document.getElementById('toasts');
    if (!region || !text) { return; }
    var div = document.createElement('div');
    div.className = 'toast toast-' + level;
    div.textContent = text;
    region.appendChild(div);
  }

  function start(button) {
    button.disabled = true;
    offerOf(button.getAttribute('data-dcapi-offer') || '')
      .then(function(offer){
        return navigator.credentials.create({ digital: { requests: [{ protocol: PROTOCOL, data: offer }] } });
      })
      .then(function(){
        toast('ok', button.getAttribute('data-dcapi-ok'));
      }, function(err){
        var name = err && err.name;
        if (name === 'NotAllowedError' || name === 'AbortError') {
          toast('info', button.getAttribute('data-dcapi-cancel'));
        } else {
          toast('bad', button.getAttribute('data-dcapi-fail'));
        }
      })
      .then(function(){ button.disabled = false; });
  }

  /* reveal shows every offer button of the document when the API is there. */
  function reveal() {
    if (!supported()) { return; }
    var buttons = document.querySelectorAll('button[data-dcapi-offer]');
    for (var i = 0; i < buttons.length; i++) { buttons[i].hidden = false; }
  }

  document.addEventListener('click', function(e){
    var b = e.target.closest ? e.target.closest('button[data-dcapi-offer]') : null;
    if (b && !b.hidden && supported()) { start(b); }
  });
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', reveal);
  } else {
    reveal();
  }
  /* htmx swaps the main region: a new result page needs the test again. */
  document.addEventListener('htmx:afterSettle', reveal);
})();
