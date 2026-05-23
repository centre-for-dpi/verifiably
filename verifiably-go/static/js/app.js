// app.js — minimal client-side behaviour.
// HTMX handles all async server interaction; this file only covers
// concerns that genuinely need the browser: toasts, theme, clipboard,
// and surfacing unhandled server errors.

(function () {
  'use strict';

  // ---- Theme toggle ----
  const THEME_KEY = 'verifiably_theme';
  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem(THEME_KEY, t); } catch (e) { /* private mode */ }
  }
  window.toggleTheme = function () {
    const cur = document.documentElement.getAttribute('data-theme') || 'light';
    applyTheme(cur === 'light' ? 'dark' : 'light');
  };
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved) applyTheme(saved);
  } catch (e) {}

  // ---- Toast ----
  let toastTimer = null;
  function toast(msg) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
  }
  window.toast = toast;

  // ---- HTMX event bindings ----
  // HX-Trigger: toast:<message>  →  server-initiated toast
  document.body.addEventListener('htmx:afterOnLoad', function (evt) {
    // older htmx sets HX-Trigger as a custom event; we also listen below.
  });

  // HTMX triggers custom events from HX-Trigger. Listen for both the
  // single-form (plain string "toast:msg") and the JSON form.
  document.body.addEventListener('htmx:trigger', function (evt) {
    // noop — individual events below handle specifics
  });

  // Server sends: HX-Trigger: toast:Some message  → htmx dispatches `toast:Some message` event
  // but because htmx treats the text after the colon as the event name, we also
  // accept the JSON form: HX-Trigger: {"toast":"Some message"}
  document.body.addEventListener('toast', function (evt) {
    const msg = (evt.detail && (evt.detail.value || evt.detail)) || evt.detail || '';
    if (typeof msg === 'string') toast(msg);
    else if (msg && msg.value) toast(msg.value);
  });

  // Error surface — if an HTMX request fails, show a toast instead of a silent failure.
  document.body.addEventListener('htmx:responseError', function (evt) {
    const status = evt.detail && evt.detail.xhr && evt.detail.xhr.status;
    toast('Server error' + (status ? ' (' + status + ')' : ''));
  });
  document.body.addEventListener('htmx:sendError', function () {
    toast('Network error — check your connection');
  });

  // ---- HTMX loading state — disable .btn buttons while a request is in flight ----
  // Only applies to buttons that carry the .btn class so small UI controls
  // (e.g. the × remove-field button) are left untouched.
  const LOADING_SAVED = 'data-loading-html';

  function findActionBtn(elt) {
    if (elt.tagName === 'BUTTON' && elt.classList.contains('btn')) return elt;
    if (elt.tagName === 'FORM') {
      return elt.querySelector('button.btn[type="submit"], button.btn:not([type="button"]):not([type="reset"])');
    }
    return null;
  }

  document.body.addEventListener('htmx:beforeRequest', function (e) {
    var btn = findActionBtn(e.detail.elt);
    if (!btn || btn.hasAttribute(LOADING_SAVED)) return;
    var label = btn.textContent.trim();
    btn.setAttribute(LOADING_SAVED, btn.innerHTML);
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-spinner" aria-hidden="true"></span>' + label;
  });

  document.body.addEventListener('htmx:afterRequest', function (e) {
    var btn = findActionBtn(e.detail.elt);
    if (!btn || !btn.hasAttribute(LOADING_SAVED)) return;
    if (!document.body.contains(btn)) return; // swapped out of DOM — nothing to restore
    btn.innerHTML = btn.getAttribute(LOADING_SAVED);
    btn.removeAttribute(LOADING_SAVED);
    btn.disabled = false;
  });

  // ---- Multipart upload helper (verifier QR image upload) ----
  // HTMX 2.x multipart submission is finicky on <form>-level hx-post; we drive
  // the POST directly and swap the result into #verify-result ourselves.
  window.uploadQR = function (evt) {
    evt.preventDefault();
    const form = evt.target;
    const action = form.getAttribute('hx-post') || '/verifier/verify/direct';
    const data = new FormData(form);
    fetch(action, { method: 'POST', body: data, headers: { 'HX-Request': 'true' } })
      .then((r) => r.text())
      .then((html) => {
        const tgt = document.getElementById('verify-result');
        if (tgt) tgt.innerHTML = html;
      })
      .catch((err) => toast('Upload failed: ' + err.message));
    return false;
  };

  // ---- Clipboard helper (exposed for onclick attributes) ----
  window.copyText = function (text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        () => toast('Copied to clipboard'),
        () => toast('Copy failed — select manually')
      );
    } else {
      toast('Clipboard not available');
    }
  };

  // ---- Schema picker filter (verifier: Build custom request) ----
  // Wires the filter chips + search input that sit above a
  // [data-schema-select] dropdown. Each <option> carries data-std and
  // data-search; we hide options that don't match. Pure client-side;
  // the existing HTMX hx-post on the select still fires on change.
  function initSchemaPicker() {
    const sel = document.querySelector('[data-schema-select]');
    if (!sel) return;
    const chips = document.querySelectorAll('[data-schema-filter] .chip');
    const search = document.querySelector('[data-schema-search]');
    const emptyMsg = document.getElementById('schema-filter-empty');
    let activeStd = 'all';

    function apply() {
      const q = (search && search.value || '').trim().toLowerCase();
      let visible = 0;
      let firstVisible = null;
      sel.querySelectorAll('option').forEach((o) => {
        if (!o.value) { o.hidden = false; return; } // keep the placeholder
        const std = o.getAttribute('data-std') || '';
        const corpus = o.getAttribute('data-search') || '';
        const matchesStd = activeStd === 'all' || std === activeStd;
        const matchesQ = !q || corpus.indexOf(q) !== -1;
        const show = matchesStd && matchesQ;
        o.hidden = !show;
        if (show) { visible++; if (!firstVisible) firstVisible = o; }
      });
      if (emptyMsg) emptyMsg.style.display = visible === 0 ? 'block' : 'none';
      // If the currently-selected option got hidden, clear the selection so
      // the placeholder shows again — avoids a confusing state where the
      // visible options don't include the selected one.
      const current = sel.querySelector('option[value="' + CSS.escape(sel.value) + '"]');
      if (current && current.hidden) { sel.value = ''; }
    }

    chips.forEach((c) => {
      c.addEventListener('click', () => {
        chips.forEach((x) => x.classList.remove('active'));
        c.classList.add('active');
        activeStd = c.getAttribute('data-std') || 'all';
        apply();
      });
    });
    if (search) {
      search.addEventListener('input', apply);
    }
    apply();
  }
  initSchemaPicker();
  // Re-run after htmx swaps so the picker works even when the verifier
  // page is loaded via hx-boost.
  document.body.addEventListener('htmx:load', initSchemaPicker);

  // ---- Wallet search filter ----
  // Each held credential card carries data-search with a lowercased
  // corpus (title + issuer + type + format + claim names/values). Typing
  // hides cards whose corpus doesn't contain the query. Pure client
  // side; the HTMX swap that re-renders the wallet fragment re-runs this
  // on htmx:load.
  function initWalletSearch() {
    const input = document.querySelector('[data-wallet-search]');
    if (!input) return;
    const formatFilter = document.querySelector('[data-wallet-format-filter]');
    const cards = document.querySelectorAll('[data-wallet-card]');
    const empty = document.getElementById('wallet-search-empty');
    const counter = document.getElementById('wallet-search-count');
    function apply() {
      const q = input.value.trim().toLowerCase();
      const f = formatFilter ? formatFilter.value : 'all';
      let visible = 0;
      cards.forEach((c) => {
        const corpus = c.getAttribute('data-search') || '';
        const fmt = c.getAttribute('data-format') || '';
        const matchesQ = !q || corpus.indexOf(q) !== -1;
        const matchesF = f === 'all' || fmt === f;
        const show = matchesQ && matchesF;
        c.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      if (empty) empty.style.display = visible === 0 ? 'block' : 'none';
      if (counter) {
        const filtered = (q || (formatFilter && formatFilter.value !== 'all'));
        if (filtered && visible !== cards.length) {
          counter.textContent = visible + ' of ' + cards.length;
          counter.style.display = '';
        } else {
          counter.style.display = 'none';
        }
      }
    }
    input.addEventListener('input', apply);
    if (formatFilter) formatFilter.addEventListener('change', apply);
    apply();
  }
  initWalletSearch();
  document.body.addEventListener('htmx:load', initWalletSearch);
})();
