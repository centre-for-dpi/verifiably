// SPDX-License-Identifier: Apache-2.0
//
// wallet.js is the browser side of the wallet portal (ADR-021 decision 4
// and ADR-020 decision 4). It does four jobs:
//
//   1. It creates the holder key pair with WebCrypto. The private key is
//      not extractable. It stays in IndexedDB of this browser.
//   2. It derives one AES-GCM content key from that key pair. The server
//      never sees the content key.
//   3. It reads and writes the ciphertext blobs of the server.
//   4. It offers a file upload and a paste box, so a citizen moves a
//      credential without a camera.
//
// The envelope format matches services/wallet-portal/internal/blobs:
//
//   {"v":1,"kdf":"HKDF-SHA256","alg":"A256GCM","iv":"<b64url>","ct":"<b64url>"}
//
// The file uses no framework and no build step. It is plain JavaScript.
"use strict";

const VCA = (() => {
  const VERSION = 1;
  const ALG = "A256GCM";
  const KDF = "HKDF-SHA256";
  const INFO = "vca-wallet-blob-v1";
  const SALT = "vca-wallet-portal";
  const DB_NAME = "vca-wallet";
  const DB_STORE = "keys";
  const KEY_ID = "holder";

  // b64url encodes bytes without padding.
  function b64url(bytes) {
    let text = "";
    const view = new Uint8Array(bytes);
    for (let i = 0; i < view.length; i += 1) {
      text += String.fromCharCode(view[i]);
    }
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // unb64url decodes a base64url string into bytes.
  function unb64url(text) {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(padded + "===".slice((padded.length + 3) % 4));
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) {
      out[i] = raw.charCodeAt(i);
    }
    return out;
  }

  // openDB opens the key database of this origin.
  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(DB_STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  // dbGet reads one value of the key store.
  function dbGet(db, id) {
    return new Promise((resolve, reject) => {
      const req = db.transaction(DB_STORE, "readonly").objectStore(DB_STORE).get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  // dbPut writes one value of the key store.
  function dbPut(db, id, value) {
    return new Promise((resolve, reject) => {
      const req = db.transaction(DB_STORE, "readwrite").objectStore(DB_STORE).put(value, id);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  // holderKey returns the holder key pair of this browser. It creates
  // the pair on the first call. The private key is not extractable, so
  // no script and no server can read it.
  async function holderKey() {
    const db = await openDB();
    const held = await dbGet(db, KEY_ID);
    if (held && held.privateKey) {
      return held;
    }
    const pair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    await dbPut(db, KEY_ID, pair);
    return pair;
  }

  // contentKey derives the AES-GCM key of the blobs. The shared secret
  // comes from an ECDH derivation over the holder key pair. The private
  // key never leaves the browser, so the secret never leaves it either.
  async function contentKey() {
    const pair = await holderKey();
    const secret = await crypto.subtle.deriveBits(
      { name: "ECDH", public: pair.publicKey },
      pair.privateKey,
      256,
    );
    const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new TextEncoder().encode(SALT),
        info: new TextEncoder().encode(INFO),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  // publicJWK returns the public holder key as a JWK. The wallet
  // authentication service takes it in RegisterHolderKey.
  async function publicJWK() {
    const pair = await holderKey();
    return crypto.subtle.exportKey("jwk", pair.publicKey);
  }

  // seal encrypts text and returns the envelope.
  async function seal(text) {
    const key = await contentKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(text),
    );
    return { v: VERSION, kdf: KDF, alg: ALG, iv: b64url(iv), ct: b64url(ct) };
  }

  // open decrypts one envelope and returns the text.
  async function open(envelope) {
    if (!envelope || envelope.v !== VERSION || envelope.alg !== ALG || envelope.kdf !== KDF) {
      throw new Error("the envelope is not valid");
    }
    const key = await contentKey();
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64url(envelope.iv) },
      key,
      unb64url(envelope.ct),
    );
    return new TextDecoder().decode(plain);
  }

  // csrfToken reads the page token of the wallet pages.
  function csrfToken() {
    const field = document.querySelector('input[name="csrf_token"]');
    return field ? field.value : "";
  }

  // base returns the URL prefix of the wallet pages.
  function base() {
    const root = document.body ? document.body.dataset.walletPrefix : "";
    return root || "/wallet";
  }

  // list reads every blob of the citizen and decrypts each one.
  async function list() {
    const resp = await fetch(base() + "/blobs", { headers: { Accept: "application/json" } });
    if (!resp.ok) {
      throw new Error("the wallet store did not answer");
    }
    const body = await resp.json();
    const out = [];
    for (const rec of body.blobs || []) {
      try {
        out.push({ id: rec.id, storedAt: rec.stored_at, text: await open(rec.envelope) });
      } catch (err) {
        out.push({ id: rec.id, storedAt: rec.stored_at, error: String(err.message || err) });
      }
    }
    return out;
  }

  // save encrypts text and writes it under id.
  async function save(id, text) {
    const envelope = await seal(text);
    const resp = await fetch(base() + "/blobs/" + encodeURIComponent(id), {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
      body: JSON.stringify(envelope),
    });
    if (!resp.ok) {
      throw new Error("the wallet store did not take the credential");
    }
    return resp.json();
  }

  // remove deletes one blob.
  async function remove(id) {
    const resp = await fetch(base() + "/blobs/" + encodeURIComponent(id), {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrfToken() },
    });
    if (!resp.ok && resp.status !== 204) {
      throw new Error("the wallet store did not remove the credential");
    }
  }

  // newID returns a random blob id.
  function newID() {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    return b64url(bytes).replace(/[^A-Za-z0-9_-]/g, "");
  }

  // say writes one sentence into the status region of the page.
  function say(sentence) {
    const region = document.getElementById("wallet-status");
    if (region) {
      region.textContent = sentence;
    }
  }

  // wire connects the file upload and the paste box of the page. Both
  // are the fallback for a browser with no camera.
  function wire() {
    const file = document.getElementById("wallet-file");
    if (file) {
      file.addEventListener("change", async () => {
        const chosen = file.files && file.files[0];
        if (!chosen) {
          return;
        }
        try {
          const text = (await chosen.text()).trim();
          await save(newID(), text);
          say("The wallet stored the credential of the file.");
        } catch (err) {
          say("The file did not load. " + String(err.message || err));
        }
      });
    }
    const paste = document.getElementById("wallet-paste");
    const button = document.getElementById("wallet-paste-save");
    if (paste && button) {
      button.addEventListener("click", async () => {
        const text = paste.value.trim();
        if (!text) {
          say("Paste the credential text first.");
          return;
        }
        try {
          await save(newID(), text);
          paste.value = "";
          say("The wallet stored the credential you pasted.");
        } catch (err) {
          say("The wallet did not store the text. " + String(err.message || err));
        }
      });
    }
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", wire);
  }

  return { b64url, unb64url, holderKey, contentKey, publicJWK, seal, open, list, save, remove, newID, wire, say };
})();

if (typeof window !== "undefined") {
  window.VCA = VCA;
}
