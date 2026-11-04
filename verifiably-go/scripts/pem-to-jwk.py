#!/usr/bin/env python3
"""Convert an RSA private key in PEM (on stdin) to a compact JWK on stdout.

walt.id's wallet reads its token-signing key as a JWK embedded in auth.conf.
This emits exactly the field set the previously-committed key carried
(p, kty, q, d, e, kid, qi, dp, dq, n) so the rendered file is shaped like the
one it replaces.

Deliberately stdlib-only: it runs from deploy.sh on a clean host where the only
guaranteed Python is the system interpreter, so pulling in `cryptography` or
`jwcrypto` would add a provisioning step to the demo quickstart.
"""

import base64
import hashlib
import json
import re
import sys


def b64u(n: int) -> str:
    """Base64url-encode a non-negative integer, minimal length, no padding."""
    blen = (n.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(n.to_bytes(blen, "big")).decode().rstrip("=")


def read_der(pem: bytes) -> bytes:
    body = re.sub(rb"-----(BEGIN|END)[^-]+-----", b"", pem)
    return base64.b64decode(re.sub(rb"\s+", b"", body))


class DER:
    """Just enough DER to walk an RSAPrivateKey / PKCS#8 wrapper."""

    def __init__(self, buf: bytes):
        self.b, self.i = buf, 0

    def _len(self) -> int:
        n = self.b[self.i]
        self.i += 1
        if n < 0x80:
            return n
        count = n & 0x7F
        val = int.from_bytes(self.b[self.i:self.i + count], "big")
        self.i += count
        return val

    def tag(self, expected: int) -> bytes:
        assert self.b[self.i] == expected, f"expected tag {expected:#x} at {self.i}"
        self.i += 1
        ln = self._len()
        out = self.b[self.i:self.i + ln]
        self.i += ln
        return out

    def seq(self) -> "DER":
        return DER(self.tag(0x30))

    def int_(self) -> int:
        return int.from_bytes(self.tag(0x02), "big")


def rsa_params(der: bytes):
    d = DER(der).seq()
    first = d.int_()  # version
    if first == 0 and d.b[d.i] == 0x30:
        # PKCS#8: version, AlgorithmIdentifier, OCTET STRING(privateKey)
        d.tag(0x30)
        return rsa_params(d.tag(0x04))
    return [first] + [d.int_() for _ in range(8)]


def main() -> int:
    pem = sys.stdin.buffer.read()
    if not pem.strip():
        print("no PEM on stdin", file=sys.stderr)
        return 1
    _ver, n, e, d, p, q, dp, dq, qi = rsa_params(read_der(pem))

    jwk = {
        "p": b64u(p), "kty": "RSA", "q": b64u(q), "d": b64u(d), "e": b64u(e),
        "kid": "", "qi": b64u(qi), "dp": b64u(dp), "dq": b64u(dq), "n": b64u(n),
    }
    # RFC 7638 thumbprint: the canonical kid for an RSA key.
    thumb = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
                       separators=(",", ":"), sort_keys=True).encode()
    jwk["kid"] = base64.urlsafe_b64encode(hashlib.sha256(thumb).digest()).decode().rstrip("=")

    sys.stdout.write(json.dumps(jwk, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
