// SPDX-License-Identifier: Apache-2.0
//
// Camera QR scanner of the verifier ingestion page (ADR-023 decision 6).
// It is lifted from verifiably-go/static/js/scanner.js and reduced to one
// purpose: read a QR code with the camera and post only the decoded text.
//
// The camera frames never leave the device. The page draws each frame on
// an offscreen canvas, gives the pixels to jsQR, and posts the decoded
// text to the ingest endpoint. The page also works without a camera: the
// file upload and the paste box post to the same endpoint.

(function () {
  'use strict';

  var active = null; // { stream: MediaStream, handle: number }

  function el(id) {
    return document.getElementById(id);
  }

  function say(text) {
    var status = el('scan-status');
    if (status) status.textContent = text;
  }

  function stop() {
    if (!active) return;
    if (active.handle) cancelAnimationFrame(active.handle);
    if (active.stream) active.stream.getTracks().forEach(function (t) { t.stop(); });
    active = null;
    var video = el('scan-video');
    if (video) video.hidden = true;
    var button = el('scan-start');
    if (button) {
      button.textContent = 'Start camera';
      button.setAttribute('aria-expanded', 'false');
    }
  }
  window.vcaStopScan = stop;

  // post sends the decoded text and swaps the result region.
  function post(text) {
    var form = new FormData();
    form.append('payload', text);
    return fetch(el('scan-form').getAttribute('data-ingest'), { method: 'POST', body: form })
      .then(function (resp) { return resp.text(); })
      .then(function (html) {
        var target = el('scan-result');
        if (target) target.innerHTML = html;
      });
  }

  // ready waits until the video element delivers pixels.
  function ready(video, deadline) {
    return new Promise(function (resolve) {
      (function check() {
        if (video.readyState >= 2 && video.videoWidth > 0 && video.videoHeight > 0) return resolve(true);
        if (Date.now() > deadline) return resolve(false);
        setTimeout(check, 50);
      })();
    });
  }

  function start() {
    var button = el('scan-start');
    var video = el('scan-video');
    if (!button || !video) return;
    if (active) { stop(); return; }
    if (typeof window.jsQR !== 'function') {
      say('The QR reader did not load. Reload the page, or upload an image below.');
      return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      say('This browser has no camera API. Upload an image below.');
      return;
    }
    say('Asking for camera permission.');
    navigator.mediaDevices
      .getUserMedia({ video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false })
      .then(function (stream) {
        video.srcObject = stream;
        video.hidden = false;
        var played = video.play();
        if (played && played.catch) played.catch(function () {});
        return ready(video, Date.now() + 5000).then(function (ok) {
          if (!ok) {
            stream.getTracks().forEach(function (t) { t.stop(); });
            say('The camera sent no frame. Upload an image below.');
            return;
          }
          active = { stream: stream, handle: null };
          button.textContent = 'Stop camera';
          button.setAttribute('aria-expanded', 'true');
          say('Scanning. Hold the QR code inside the frame.');
          scan(video);
        });
      })
      .catch(function (e) {
        say('The camera is not available: ' + (e.message || e.name));
      });
  }

  function scan(video) {
    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d', { willReadFrequently: true });
    var frames = 0;
    (function tick() {
      if (!active) return;
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      if (canvas.width && canvas.height) {
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        var image = ctx.getImageData(0, 0, canvas.width, canvas.height);
        var code = window.jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
        if (code && code.data) {
          stop();
          say('The page read the code. Checking it now.');
          post(code.data).catch(function (err) { say('The check failed: ' + err.message); });
          return;
        }
        frames++;
        if (frames % 30 === 0) say('Scanning. ' + frames + ' frames so far.');
      }
      active.handle = requestAnimationFrame(tick);
    })();
  }

  document.addEventListener('DOMContentLoaded', function () {
    var button = el('scan-start');
    if (button) button.addEventListener('click', start);
  });
})();
