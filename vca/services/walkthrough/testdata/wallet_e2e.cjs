// SPDX-License-Identifier: Apache-2.0
//
// wallet_e2e.cjs drives wallet.js in a headless Chromium (ADR-004
// decision 6). The Go test TestWalletScriptInChromium starts the
// walkthrough deployment and runs this file once per phase. Both phases
// share one browser profile, so the signing key of the holder stays in
// IndexedDB between them.
//
//   claim    signs the holder in, pastes the offer, and lets wallet.js
//            sign the proof of the claim with its own key.
//   present  pastes the request of the verifier and lets wallet.js sign
//            the key binding of the answer.
//
// The only argument is a JSON object: phase, holder, link, pin, profile.
// The file prints one JSON line with what it saw.
"use strict";

const { chromium } = require("playwright");

// signIn opens the home of the holder pair and follows the sign in of
// its identity provider back to the wallet.
async function signIn(page, holder) {
  await page.goto(holder + "/");
  await page.getByRole("link", { name: "Sign in" }).first().click();
  await page.waitForURL(/\/wallet\//);
}

// paste opens the paste page of the wallet and sends one link.
async function paste(page, holder, link) {
  await page.goto(holder + "/wallet/claim");
  const form = page.locator('form[action$="/wallet/claim/offer"]');
  await form.locator('textarea[name="offer"], input[name="offer"]').fill(link);
  await form.locator('button[type="submit"]').first().click();
  await page.waitForLoadState("domcontentloaded");
}

// claim pastes the offer and submits the claim form, which wallet.js
// takes over: it signs the proof and seals the credential.
async function claim(page, input) {
  await signIn(page, input.holder);
  await paste(page, input.holder, input.link);
  const form = page.locator("form[data-browser-claim]");
  await form.waitFor();
  if (input.pin) {
    await form.locator('input[name="pin"]').fill(input.pin);
  }
  await Promise.all([
    page.waitForURL((url) => url.pathname === "/wallet/"),
    form.locator('button[type="submit"]').first().click(),
  ]);
  const key = await page.evaluate(async () => window.VCA.signingJWK());
  const blobs = await page.evaluate(async () => (await window.VCA.list()).length);
  return { key: key.kty + "/" + key.crv, blobs, page: await page.locator("main").innerText() };
}

// present pastes the request and submits the consent form, which
// wallet.js takes over: it signs the key binding first.
async function present(page, input) {
  await paste(page, input.holder, input.link);
  const form = page.locator("form[data-key-binding]");
  await form.waitFor();
  await Promise.all([
    page.waitForURL((url) => url.pathname.endsWith("/present") || url.pathname.includes("/history")),
    form.locator('button[type="submit"]:not([formaction])').first().click(),
  ]);
  await page.getByText("The verifier has your answer.").waitFor();
  return { page: await page.locator("main").innerText() };
}

async function main() {
  const input = JSON.parse(process.argv[2]);
  const context = await chromium.launchPersistentContext(input.profile, { headless: true });
  const page = context.pages()[0] || (await context.newPage());
  page.setDefaultTimeout(input.timeout || 20000);
  const errors = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  try {
    const seen = input.phase === "claim" ? await claim(page, input) : await present(page, input);
    seen.errors = errors;
    process.stdout.write(JSON.stringify(seen) + "\n");
  } finally {
    await context.close();
  }
}

main().catch((err) => {
  process.stderr.write(String((err && err.stack) || err) + "\n");
  process.exit(1);
});
