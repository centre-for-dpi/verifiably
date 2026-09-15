#!/usr/bin/env python3
"""
Minimal citizen service for exercising the "API" bulk-issuance source.

Reads from the existing citizens-postgres database (same one the DB source
uses) and exposes JSON endpoints shaped to match several walt.id schemas.
Each endpoint returns a bare JSON array of objects — the exact shape the
app's bulk.go fetchJSONRows expects, so the URL can be pasted straight
into the issuer's "API" bulk form.

Usage:
  CITIZENS_DSN=postgres://citizens:$CITIZENS_PG_PASSWORD@localhost:5435/citizens \
    python3 citizen_service.py --port 8099

  # inside docker, reach it via host.docker.internal:8099 (verifiably-go
  # already has that alias wired in its --add-host line)

Endpoints:
  GET /health                           → {ok:true}
  GET /api/mortgage-eligibility[?limit] → MortgageEligibility shape
  GET /api/verifiable-id[?limit]        → VerifiableId shape
  GET /api/hotel-reservation[?limit]    → HotelReservation shape
  GET /api/mortgage-simple[?limit]      → [{holder:"..."}] one-field shape
  GET /api/farmer-id[?limit]            → custom farmer shape (only citizens
                                          with farm_id populated)

Optional bearer-token auth: set CITIZENS_API_TOKEN and every /api/* request
must send `Authorization: Bearer <token>`. The bulk form has an "auth
header" input — paste `Bearer your-token` there.
"""

import json
import os
import sys
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("psycopg2 is required: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)


# Real password is CITIZENS_PG_PASSWORD from verifiably-go's own .env
# (generated on `deploy.sh setup`); "citizens" only matches a host that
# predates that variable.
DSN = os.environ.get(
    "CITIZENS_DSN",
    "postgres://citizens:%s@localhost:5435/citizens" % os.environ.get("CITIZENS_PG_PASSWORD", "citizens"),
)
REQUIRED_TOKEN = os.environ.get("CITIZENS_API_TOKEN", "").strip()


def fetch(sql, limit):
    # limit is already clamped to an int in [1, 500]; format it into the SQL
    # directly so psycopg2 doesn't try to consume `%` characters inside the
    # queries (several of them use `%` as postgres' modulo operator, which
    # clashes with psycopg2's parameter-substitution syntax).
    sql = sql.replace("__LIMIT__", str(int(limit)))
    with psycopg2.connect(DSN) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    # RealDictCursor gives dicts; coerce non-serializable types to str.
    out = []
    for r in rows:
        row = {}
        for k, v in r.items():
            if v is None:
                row[k] = ""
            elif hasattr(v, "isoformat"):
                row[k] = v.isoformat()
            else:
                row[k] = v if isinstance(v, (str, int, float, bool)) else str(v)
        out.append(row)
    return out


ROUTES = {
    "/api/mortgage-eligibility": """
        SELECT
          CASE gender WHEN 'Male' THEN 'Mr' WHEN 'Female' THEN 'Mrs' ELSE '' END AS salutation,
          first_name                      AS "firstName",
          last_name                       AS "familyName",
          email                           AS "emailAddress",
          date_of_birth::text             AS "dateOfBirth",
          (400000 + (id * 1750) % 500000) AS "purchasePrice",
          (60000  + (id * 320)  % 120000) AS "totalIncome",
          (320000 + (id * 1400) % 400000) AS "mortgageAmount",
          CASE (id % 4) WHEN 0 THEN 'none' WHEN 1 THEN 'vehicle' WHEN 2 THEN 'savings' ELSE 'shares' END AS "additionalCollateral",
          LPAD((id * 37)::text, 5, '0')   AS "postCodeProperty"
        FROM citizens ORDER BY id LIMIT __LIMIT__
    """,
    "/api/verifiable-id": """
        SELECT
          first_name          AS "firstName",
          last_name           AS "familyName",
          date_of_birth::text AS "dateOfBirth",
          gender              AS gender,
          place_of_birth      AS "placeOfBirth",
          address             AS "currentAddress",
          national_id         AS "personalIdentifier",
          first_name || ' ' || last_name AS "nameAndFamilyNameAtBirth"
        FROM citizens WHERE address IS NOT NULL ORDER BY id LIMIT __LIMIT__
    """,
    "/api/hotel-reservation": """
        SELECT
          first_name           AS "firstName",
          last_name            AS "familyName",
          date_of_birth::text  AS "dateOfBirth",
          place_of_birth       AS "placeOfBirth",
          'Suite ' || (100 + id % 400)::text || ', Hotel Sample' AS "currentAddress"
        FROM citizens ORDER BY id LIMIT __LIMIT__
    """,
    "/api/mortgage-simple": """
        SELECT first_name || ' ' || last_name AS holder
        FROM citizens ORDER BY id LIMIT __LIMIT__
    """,
    "/api/farmer-id": """
        SELECT
          first_name || ' ' || last_name AS holder,
          farm_id                         AS "farmId",
          farm_location                   AS location,
          COALESCE(farm_size_hectares::text, '') AS hectares,
          COALESCE(primary_crops, '')     AS crops,
          farm_registration_date::text    AS "registeredOn"
        FROM citizens WHERE farm_id IS NOT NULL ORDER BY id LIMIT __LIMIT__
    """,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"citizen-service {self.address_string()} {fmt % args}\n")

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self):
        if not REQUIRED_TOKEN:
            return True
        got = (self.headers.get("Authorization") or "").strip()
        expected = f"Bearer {REQUIRED_TOKEN}"
        return got == expected

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            self._send_json({"ok": True, "routes": sorted(ROUTES.keys())})
            return
        if url.path not in ROUTES:
            self._send_json({"error": "unknown route", "path": url.path}, status=404)
            return
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, status=401)
            return
        q = parse_qs(url.query)
        try:
            limit = max(1, min(500, int(q.get("limit", ["20"])[0])))
        except ValueError:
            limit = 20
        try:
            rows = fetch(ROUTES[url.path], limit)
        except Exception as exc:
            self._send_json({"error": "db query failed", "detail": str(exc)}, status=500)
            return
        self._send_json(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8099")))
    ap.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    args = ap.parse_args()
    srv = HTTPServer((args.host, args.port), Handler)
    print(f"citizen-service listening on http://{args.host}:{args.port}")
    print(f"  DSN         : {DSN}")
    print(f"  auth        : {'bearer token required' if REQUIRED_TOKEN else 'open (no auth)'}")
    print(f"  routes      : {sorted(ROUTES.keys())}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
