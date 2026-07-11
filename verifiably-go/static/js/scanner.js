// Camera-based QR scanner for the verifier's "Scan QR" card.
// Strategy:
//   1. startScan() opens a user-facing camera stream via getUserMedia.
//   2. Each animation frame is drawn onto an offscreen canvas and fed to
//      jsQR. On the first successful decode the stream is stopped, the
//      decoded payload is POSTed to /verifier/verify/direct with
//      method=scan, and the server renders the verify-result fragment.
//   3. Errors surface as a toast — the user can retry.
//
// This replaces the old "Simulate scan" button with a real, in-browser QR
// decode. The server never sees the camera feed itself; only the decoded
// text reaches the backend.

(function () {
  // Unified scanner used by BOTH the verifier card (id=scan-*) and the
  // wallet card (id=wallet-scan-*). Each site calls its own start function
  // (startScan / startWalletScan); internally both funnel through scanInto
  // with different DOM ids and POST targets.
  let active = null; // { stream, handle, ids, postURL, postField, method }

  function stopActive() {
    if (!active) return;
    if (active.handle) cancelAnimationFrame(active.handle);
    if (active.stream) active.stream.getTracks().forEach((t) => t.stop());
    const vid = document.getElementById(active.ids.video);
    if (vid) vid.style.display = 'none';
    const btn = document.getElementById(active.ids.btn);
    if (btn) btn.textContent = 'Start camera →';
    active = null;
  }

  // Back-compat export so older call sites that imported stopScan still work.
  window.stopScan = stopActive;

  async function postAndRender(postURL, formFields, targetId) {
    const form = new FormData();
    for (const [k, v] of Object.entries(formFields)) form.append(k, v);
    const resp = await fetch(postURL, {
      method: 'POST',
      body: form,
      headers: { 'HX-Request': 'true' },
    });
    const html = await resp.text();
    const target = document.getElementById(targetId);
    if (target) target.innerHTML = html;
    return resp;
  }

  // Wait for the video element to report non-zero dimensions. Polling
  // readyState >= HAVE_CURRENT_DATA is reliable across browsers; this fixes
  // scans silently failing because the first 2-3 frames were captured before
  // the video stream had actually delivered pixels.
  async function awaitVideoReady(video, timeoutMs = 5000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (video.readyState >= 2 && video.videoWidth > 0 && video.videoHeight > 0) return true;
      await new Promise((r) => setTimeout(r, 50));
    }
    return false;
  }

  async function scanInto(opts) {
    // opts: { ids:{btn,video,status}, postURL, targetId, extraFields }
    const btn = document.getElementById(opts.ids.btn);
    const vid = document.getElementById(opts.ids.video);
    const status = document.getElementById(opts.ids.status);
    if (!vid || !status || !btn) return;
    if (active) { stopActive(); return; }

    if (typeof window.jsQR !== 'function') {
      status.textContent = 'QR library failed to load. Reload the page.';
      return;
    }

    status.textContent = 'Requesting camera permission…';
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      });
    } catch (e) {
      status.textContent = 'Camera unavailable: ' + (e.message || e.name);
      return;
    }

    vid.srcObject = stream;
    vid.style.display = 'block';
    await vid.play().catch(() => {});
    const ready = await awaitVideoReady(vid);
    if (!ready) {
      stream.getTracks().forEach((t) => t.stop());
      status.textContent = 'Camera stream never delivered a frame.';
      return;
    }

    active = { stream, handle: null, ids: opts.ids, postURL: opts.postURL };
    btn.textContent = 'Stop scanning';
    status.textContent = `Scanning (${vid.videoWidth}×${vid.videoHeight})…`;

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    let frames = 0;

    function tick() {
      if (!active) return;
      canvas.width = vid.videoWidth;
      canvas.height = vid.videoHeight;
      if (canvas.width && canvas.height) {
        ctx.drawImage(vid, 0, 0, canvas.width, canvas.height);
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        // jsQR sometimes misses a valid code depending on orientation; let
        // it try both polarities on the slow path.
        const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
        if (code && code.data) {
          const text = code.data;
          stopActive();
          // Fill-the-field mode: the decoded QR is dropped into a form field and
          // the page's own flow takes over (no POST). Used by the present page,
          // where the QR is an openid4vp:// request the holder still reviews.
          if (opts.fillField) {
            const target = document.getElementById(opts.fillField);
            if (target) {
              target.value = text;
              target.dispatchEvent(new Event('input', { bubbles: true }));
            }
            status.textContent = 'Request loaded — review below.';
            return;
          }
          status.textContent = 'Got it. Verifying…';
          postAndRender(opts.postURL, { ...opts.extraFields, [opts.payloadField || 'credential_data']: text }, opts.targetId)
            .catch((err) => { status.textContent = 'Verify failed: ' + err.message; });
          return;
        }
        frames++;
        if (frames % 30 === 0) status.textContent = `Scanning… (${frames} frames)`;
      }
      active.handle = requestAnimationFrame(tick);
    }
    active.handle = requestAnimationFrame(tick);
  }

  // Verifier direct-verify scan: posts method=scan + credential_data to
  // /verifier/verify/direct.
  window.startScan = function () {
    scanInto({
      ids: { btn: 'scan-btn', video: 'scan-video', status: 'scan-status' },
      postURL: '/verifier/verify/direct',
      targetId: 'verify-result',
      extraFields: { method: 'scan' },
      payloadField: 'credential_data',
    });
  };

  // Holder-side offer scan: the decoded QR IS the offer URI; post it to
  // /holder/wallet/paste so the server treats it as a paste.
  window.startWalletScan = function () {
    scanInto({
      ids: { btn: 'wallet-scan-btn', video: 'wallet-scan-video', status: 'wallet-scan-status' },
      postURL: '/holder/wallet/paste',
      targetId: 'wallet-body',
      extraFields: {},
      payloadField: 'offer_uri',
    });
  };

  // Holder present-request scan: the decoded QR IS the verifier's openid4vp://
  // request. Fill the paste textarea (no POST) so the existing resolve/consent
  // flow proceeds exactly as if the holder had pasted the link.
  window.startPresentScan = function () {
    scanInto({
      ids: { btn: 'present-scan-btn', video: 'present-scan-video', status: 'present-scan-status' },
      fillField: 'inji-present-request',
    });
  };
})();
