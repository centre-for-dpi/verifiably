// SPDX-License-Identifier: Apache-2.0
//
// layout_e2e.cjs renders pages of the walkthrough in a headless Chromium
// at a width of 1280 px and reports every element that overflows the
// content column (review finding 7). The Go test TestLayout runs it.
//
// The standard input is a JSON object with pages, a list of {name, url,
// html}. The script answers a request for url with html, so the page
// loads the real styles of its pair while the Go client keeps the
// sessions. It opens every disclosure before it measures.
// The file prints one JSON line: {overflow: {name: [problems]}}.
"use strict";

const { chromium } = require("playwright");

// measure lists the elements of the main landmark that reach past it,
// and each table frame or card that scrolls sideways.
async function measure(page) {
  return page.evaluate(() => {
    for (const d of document.querySelectorAll("details")) {
      d.open = true;
    }
    const out = [];
    const main = document.querySelector("main");
    if (!main) {
      return ["no main landmark"];
    }
    const label = (el) => el.tagName.toLowerCase() + (el.id ? "#" + el.id : "") +
      (el.className && typeof el.className === "string" ? "." + el.className.split(" ")[0] : "");
    if (main.scrollWidth > main.clientWidth + 1) {
      out.push("main scrolls: " + main.scrollWidth + " > " + main.clientWidth);
    }
    for (const el of main.querySelectorAll(".table-wrap, .card, pre, table")) {
      if (el.scrollWidth > el.clientWidth + 1) {
        out.push(label(el) + " scrolls: " + el.scrollWidth + " > " + el.clientWidth);
      }
    }
    // A block of text whose words do not fit spills into its neighbour
    // even inside the column, for example a long DID in a narrow card.
    for (const el of main.querySelectorAll("p, li, dd, dt, h2, h3, summary, .credential-issuer")) {
      if (el.clientWidth > 0 && el.scrollWidth > el.clientWidth + 1) {
        out.push(label(el) + " spills: " + el.scrollWidth + " > " + el.clientWidth +
          " (" + JSON.stringify(el.textContent.trim().slice(0, 80)) + ")");
      }
    }
    const edge = main.getBoundingClientRect().right;
    for (const el of main.querySelectorAll("*")) {
      const box = el.getBoundingClientRect();
      if (box.width <= 1 || el.closest(".toast, .toasts, .sr-only, .visually-hidden")) {
        continue;
      }
      if (box.right > edge + 1) {
        out.push(label(el) + " reaches " + Math.round(box.right) + " past " + Math.round(edge));
      }
    }
    return out.slice(0, 12);
  });
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const overflow = {};
  try {
    for (const p of input.pages) {
      await page.route(p.url, (route) => route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: p.html }));
      await page.goto(p.url);
      await page.waitForLoadState("load");
      overflow[p.name] = await measure(page);
      await page.unroute(p.url);
    }
    process.stdout.write(JSON.stringify({ overflow }) + "\n");
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack ? err.stack : err) + "\n");
  process.exit(1);
});
