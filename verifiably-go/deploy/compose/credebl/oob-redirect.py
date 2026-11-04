"""Resolve a CREDEBL out-of-band invitation id to its stored URL and redirect.

CREDEBL writes one JSON document per OOB invitation into a MinIO bucket and
hands the holder a short URL pointing here; this service looks the document up
and 302s the browser at the real invitation.

Everything on the request path is attacker-controlled, so all three inputs are
validated rather than trusted:

  * `self.path` used to be concatenated straight onto the bucket URL, which let
    a caller walk out of the bucket and read any other object in the MinIO
    instance (`GET /../other-bucket/secret`).
  * the stored value used to be passed to send_header() verbatim, which is an
    open redirect and -- if the value carried CR/LF -- HTTP response splitting.
  * upstream exceptions used to be returned to the caller, leaking MinIO's
    internal hostname and object layout to an unauthenticated client.
"""

import http.server
import json
import re
import urllib.parse
import urllib.request

MINIO = "http://credebl-minio:9000/credebl-bucket"

# One flat object key, no separators: the invitation id and nothing else.
# Rejecting '/' and '.' pairs here is what keeps the request inside the bucket.
KEY_RE = re.compile(r"^/(?P<key>[A-Za-z0-9_-]{1,128}(?:\.json)?)$")

# The stored value is handed to a browser as a Location, so it has to be a
# scheme we are willing to navigate to. didcomm:// is included because Aries
# wallets register it as a handler for exactly this flow.
ALLOWED_SCHEMES = ("http", "https", "didcomm")

MAX_URL = 4096
FETCH_TIMEOUT = 10


def safe_redirect_target(value):
    """True when value is a URL this service may redirect a browser to."""
    if not isinstance(value, str) or not value or len(value) > MAX_URL:
        return False
    # Any C0 control character can split the response header, not just CR/LF.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return False
    try:
        return urllib.parse.urlparse(value).scheme in ALLOWED_SCHEMES
    except ValueError:
        return False


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        match = KEY_RE.match(self.path)
        if not match:
            self.send_error(400, "invalid invitation id")
            return

        # Rebuild the URL from the CAPTURED key rather than concatenating
        # self.path. Functionally the regex already made traversal impossible,
        # but taint analysis cannot see a regex as a sanitiser -- and neither
        # can a reader skimming the file. The tainted value never reaches
        # urlopen now, which is both provable and obvious.
        key = urllib.parse.quote(match.group("key"), safe="")
        target = f"{MINIO}/{key}"

        try:
            with urllib.request.urlopen(target, timeout=FETCH_TIMEOUT) as resp:
                oob_url = json.loads(resp.read())
        except Exception:
            self.send_error(502, "could not resolve invitation")
            return

        if not safe_redirect_target(oob_url):
            self.send_error(502, "invitation is not a usable redirect target")
            return

        self.send_response(302)
        self.send_header("Location", oob_url)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("", 3011), Handler).serve_forever()
