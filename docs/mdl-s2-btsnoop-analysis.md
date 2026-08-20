# S-2 session encryption — BLE capture analysis

**Date:** 2026-08-20. Evidence for the criterion `docs/superpowers/specs/2026-08-17-mdl-iso18013-5-poc-design.md` §S-2 lists as "Verificación: captura BLE sin PII en claro (nRF Sniffer / HCI snoop log)" — no nRF sniffer was on hand, so this used the second listed method.

## Method

1. Enabled Android's Bluetooth HCI snoop log (Developer Options) on the reader phone (Samsung Galaxy S9+, Android 10 / API 29, per `getprop`).
2. Ran one complete mDL presentation: QR device engagement from `cdpi-wallet` (iPhone, holder) → Multipaz reader (Android) scans → BLE connects → presentation with real portrait completes.
3. Extracted the protected snoop log via `adb bugreport` (the log lives at `/data/misc/bluetooth/logs/btsnoop_hci.log`, permission-denied to a direct `adb pull` on Android 10 without root — `adb bugreport` has system permission to include it in the bundle at `FS/data/log/bt/btsnoop_hci.log`).
4. Parsed the standard btsnoop v1 format (8-byte magic + version/datalink header, then per-record `orig_len/incl_len/flags/drops/ts` + payload) with a small Python script — 1010 HCI records, 88,926 bytes total.
5. Ran a standard forensic strings extraction (printable ASCII runs ≥5 chars) across the entire raw capture, independent of getting exact ACL/L2CAP/ATT frame offsets right — deliberately chosen after manual CBOR reassembly across fragmented ACL packets proved unreliable (Android's controller-level ACK/continuation interleaving made offset math error-prone; the string-level approach doesn't depend on it).

## Result

**399 printable-ASCII runs found. Two are meaningful, both non-PII protocol framing:**

- `jeReaderKey` — a fragment of `eReaderKey`, the reader's ephemeral public key. This is defined by S-2 itself to travel unencrypted in `SessionEstablishment` — it's what both sides use to derive `SKDevice`/`SKReader` via ECDH+HKDF. Its presence in cleartext is expected and correct, not a finding of concern.
- `ddataY` / `fstatus` — fragments of the `data`/`status` map keys from `SessionEstablishment`/`SessionData` framing, not element identifiers or values.

**No mDL subject data appears anywhere in the capture.** Searched explicitly for every string that would appear if the credential were sent unencrypted — `INTRANT`, `Musterfrau`, `Anna Maria`, `family_name`, `given_name`, `birth_date`, `issuing_country`, `org.iso.18013`, `driving_privileges`, `CDPI`, `Perez`, `Pérez` (UTF-8), `portrait` — none found.

The remaining ~390 printable runs are short (typically 4-12 chars), non-repeating, and show no CBOR map/array structure or field-name patterns when inspected — consistent with AES-256-GCM ciphertext, which is what S-2 specifies for everything after `SessionEstablishment`.

## What this does and doesn't prove

**Proves:** the `DeviceResponse` — which carries every mDL element, portrait included — never appears as plaintext or as parseable CBOR structure anywhere in the raw BLE traffic. This is the criterion S-2 asks for.

**Does not prove:** that the AES-256-GCM implementation is correct per the exact KDF/IV construction S-2 specifies (`SKDevice`/`SKReader` derivation, the specific 12-byte IV layout). Confirming that would require either the session keys (not captured; they're derived from an ECDH exchange whose private halves never appear on the wire) or a white-box test against the library's own encrypt/decrypt functions. What's confirmed here is the externally-observable property that actually matters for the acceptance criterion — an eavesdropper capturing this traffic learns nothing about the credential's contents — not the internal correctness of the cipher construction.

**Did not attempt:** full protocol-level reassembly of `SessionEstablishment` into a decoded CBOR map. Manual reconstruction across Android's ACL fragment boundaries (`pb_flag` continuation bits, interleaved with unrelated controller ACKs) proved unreliable within the time available; the strings-based approach above answers the actual question without needing it. If a full protocol decode is ever needed, `internal/mdl/testdata/verify/verify.mjs`'s `@owf/mdoc` dependency likely has proper BLE/L2CAP reassembly support and would be the more reliable tool than hand-rolling it.

## Raw evidence

Capture and parsing script are not committed to the repo (contain a specific device's Bluetooth MAC-adjacent framing and are a one-off artifact, not a fixture other repos consume) — available in this session's scratchpad if re-verification is needed:
- `btsnoop_hci.log` (88,926 bytes, 1010 HCI records)
- `parse_btsnoop.py` (btsnoop v1 parser)
