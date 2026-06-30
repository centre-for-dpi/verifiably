"""Registries Admin Console — the registrar / data-population tier.

Reads the credential SCHEMAS an issuer created in verifiably (/api/schemas),
and for each *custom* credential lets an admin:
  - register a matching Sunbird RC entity (one entity per credential type),
  - create the holder records that back those credentials (keyed by the
    eSignet Individual ID),
  - bulk-import holder records from a CSV.

It is NOT part of verifiably and never edits the Sunbird registry config —
it only drives the Sunbird RC HTTP API.

Config (env):
  VERIFIABLY_SCHEMAS_URL  default http://verifiably-go:8080/api/schemas
  SUNBIRD_URL             default http://156.67.105.185:18091
"""
import os
import io
import csv
import json
import re
import time
import html
import threading

import httpx
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse

VERIFIABLY_SCHEMAS_URL = os.environ.get(
    "VERIFIABLY_SCHEMAS_URL", "http://verifiably-go:8080/api/registry-credentials")
SUNBIRD_URL = os.environ.get("SUNBIRD_URL", "http://156.67.105.185:18091").rstrip("/")

app = FastAPI(title="Registries Admin Console", docs_url=None, redoc_url=None)

# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def esc(s):
    return html.escape("" if s is None else str(s))


def entity_name(s):
    # Sunbird entity name = the credential's Certify key (credential_config_key_id),
    # which is also what verifiably's VERIFIABLY_REGISTRIES `entity` must match.
    return s.get("key", "")


def schema_fields(s):
    return list(s.get("fields") or [])


def fetch_schemas():
    """Credentials issuable by verifiably (Certify credential_config) -- incl. the
    auth-code creds the registry-auto path uses -- with their field names, from
    /api/registry-credentials. Normalised to {name, entity, fields, ...}."""
    with httpx.Client(timeout=20) as c:
        r = c.get(VERIFIABLY_SCHEMAS_URL)
        r.raise_for_status()
        data = r.json()
    out = []
    for s in data:
        out.append({
            "name": s.get("displayName") or s.get("key", ""),
            "entity": entity_name(s),
            "fields": schema_fields(s),
            "issuer": "",
            "std": s.get("scope", ""),
            "id": s.get("key", ""),
        })
    return out


def find_schema(entity):
    for s in fetch_schemas():
        if s["entity"] == entity:
            return s
    return None


# ----------------------------------------------------------------------------
# Sunbird RC
# ----------------------------------------------------------------------------
def sb_post(path, body, timeout=30, tries=4):
    """POST to Sunbird with retry/backoff (mirrors etl_citizens.py)."""
    last = "no-attempt"
    for a in range(tries):
        try:
            with httpx.Client(timeout=timeout) as c:
                r = c.post(SUNBIRD_URL + path, json=body)
            return r.status_code, r.text
        except Exception as e:  # noqa: BLE001
            last = str(e)
            time.sleep(1.0 + a)
    return -1, "retries-exhausted: " + last


def schema_json(entity, fields):
    props = {"individualId": {"type": "string", "title": "Individual ID"}}
    for f in fields:
        props[f] = {"type": "string", "title": f}
    return {
        "$schema": "http://json-schema.org/draft-07/schema", "type": "object",
        "properties": {entity: {"$ref": f"#/definitions/{entity}"}},
        "required": [entity], "title": entity,
        "definitions": {entity: {
            "$id": f"#/properties/{entity}", "type": "object", "title": entity,
            "required": ["individualId"], "properties": props}},
        "_osConfig": {"roles": [], "inviteRoles": ["anonymous"],
                      "ownershipAttributes": [],
                      "uniqueIndexFields": ["individualId"],
                      "indexFields": ["individualId"]},
    }


def list_registered_entities():
    """Schema names currently published in Sunbird (ZzProbe ignored)."""
    st, txt = sb_post("/api/v1/Schema/search", {"filters": {}}, timeout=20, tries=2)
    names = set()
    if st == 200:
        try:
            for d in json.loads(txt).get("data", []):
                n = d.get("name")
                if n and n != "ZzProbe":
                    names.add(n)
        except Exception:  # noqa: BLE001
            pass
    return names


def entity_searchable(entity):
    st, txt = sb_post(f"/api/v1/{entity}/search", {"filters": {}}, timeout=15, tries=1)
    if st == 200:
        try:
            return isinstance(json.loads(txt).get("data"), list)
        except Exception:  # noqa: BLE001
            return False
    return False


def register_entity(entity, fields):
    body = {"name": entity, "schema": json.dumps(schema_json(entity, fields)),
            "status": "PUBLISHED"}
    return sb_post("/api/v1/Schema", body, timeout=90, tries=2)


_locks = {}
_locks_guard = threading.Lock()


def _lock_for(entity):
    with _locks_guard:
        if entity not in _locks:
            _locks[entity] = threading.Lock()
        return _locks[entity]


def ensure_entity(entity, fields, max_wait=180):
    """Register the Sunbird entity if missing, then poll until searchable."""
    if entity_searchable(entity):
        return True, "already searchable"
    with _lock_for(entity):
        if entity_searchable(entity):
            return True, "already searchable"
        st, txt = register_entity(entity, fields)
        deadline = time.time() + max_wait
        while time.time() < deadline:
            if entity_searchable(entity):
                return True, "registered + searchable"
            time.sleep(5)
        return False, f"register http={st}; not searchable after {max_wait}s: {txt[:200]}"


def create_record(entity, body):
    """UNWRAPPED flat body create."""
    return sb_post(f"/api/v1/{entity}", body, timeout=30, tries=4)


def search_records(entity, filters=None, timeout=20):
    st, txt = sb_post(f"/api/v1/{entity}/search", {"filters": filters or {}},
                      timeout=timeout, tries=2)
    if st == 200:
        try:
            return json.loads(txt).get("data", [])
        except Exception:  # noqa: BLE001
            return []
    return []


def is_duplicate(txt):
    """Sunbird signals a unique-key clash a few ways (PG 'duplicate key ...
    already exists', or a 'Duplicate' message) — match them all."""
    t = (txt or "").lower()
    return ("duplicate" in t) or ("already exists" in t)


def parse_osid(entity, txt):
    try:
        return json.loads(txt).get("result", {}).get(entity, {}).get("osid", "")
    except Exception:  # noqa: BLE001
        return ""


# ----------------------------------------------------------------------------
# bulk population sources (API / database / another registry) — mirror the
# Verifiably bulk picker: fetch rows, map columns -> entity fields, create each.
# Stateless: the mapping/apply step RE-FETCHES from the source params (carried as
# hidden inputs) rather than stashing rows.
# ----------------------------------------------------------------------------
def _stringify(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return str(v)


def fetch_json_rows(url, auth="", limit=""):
    """GET a JSON array (or {rows|data|items|results:[...]}) -> flat string rows."""
    headers = {"Accept": "application/json"}
    if auth:
        headers["Authorization"] = auth
    with httpx.Client(timeout=30, follow_redirects=True) as c:
        r = c.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()
    items = data if isinstance(data, list) else None
    if items is None and isinstance(data, dict):
        for k in ("rows", "data", "items", "results"):
            if isinstance(data.get(k), list):
                items = data[k]
                break
    if items is None:
        raise ValueError("response is not a JSON array or {rows|data|items|results}")
    n = int(limit) if str(limit).strip().isdigit() else 0
    rows = []
    for i, it in enumerate(items):
        if n and i >= n:
            break
        if isinstance(it, dict):
            rows.append({k: _stringify(v) for k, v in it.items()})
    return rows


def query_db_rows(conn, query):
    """Run a SELECT against a Postgres DSN -> flat string rows."""
    if not query.strip().lower().startswith("select"):
        raise ValueError("only SELECT queries are allowed")
    import psycopg  # lazy import so the app still boots if the driver is missing
    with psycopg.connect(conn, connect_timeout=10) as cx:
        with cx.cursor() as cur:
            cur.execute(query)
            cols = [d.name for d in cur.description]
            return [{c: _stringify(v) for c, v in zip(cols, row)} for row in cur.fetchall()]


def _flatten_os(rec):
    return {k: _stringify(v) for k, v in rec.items()
            if not (k in ("osid", "osOwner") or k.startswith("_os"))}


def fetch_registry_rows(url, entity):
    """POST <url>/api/v1/<entity>/search {filters:{}} on ANOTHER Sunbird -> rows."""
    u = url.rstrip("/")
    with httpx.Client(timeout=30) as c:
        r = c.post(u + "/api/v1/" + entity + "/search", json={"filters": {}})
        r.raise_for_status()
        data = r.json()
    rows = data.get("data") if isinstance(data, dict) else data
    if rows is None and isinstance(data, dict):
        rows = data.get(entity, [])
    return [_flatten_os(x) for x in (rows or []) if isinstance(x, dict)]


def detect_columns(rows):
    seen, s = [], set()
    for r in rows:
        for k in r.keys():
            if k not in s:
                s.add(k)
                seen.append(k)
    return seen


def _apply_mapped_rows(entity, rows, mapping):
    """create_record per row, projecting source columns onto entity fields via mapping
    (which must map individualId). Same counting/dedup as the CSV import."""
    okc = dup = fail = 0
    errs = []
    for r in rows:
        body = {}
        for field, col in mapping.items():
            if col and col in r and str(r[col]).strip() != "":
                body[field] = str(r[col]).strip()
        if not body.get("individualId"):
            fail += 1
            continue
        st, txt = create_record(entity, body)
        if st in (200, 201):
            okc += 1
        elif is_duplicate(txt):
            dup += 1
        else:
            fail += 1
            if len(errs) < 3:
                errs.append("http " + str(st) + ": " + txt[:80])
        time.sleep(0.2)
    detail = (" &middot; sample errors: " + esc("; ".join(errs))) if errs else ""
    msg = ("Import complete: <b>" + str(okc) + "</b> created, <b>" + str(dup)
           + "</b> duplicates, <b>" + str(fail) + "</b> failed." + detail)
    cls = "ok" if fail == 0 else ("warn" if okc or dup else "err")
    return msg, cls


def _mapping_page(s, entity, action, rows, hidden):
    """Render the column->field mapping step. `hidden` carries the source params so
    the apply post re-fetches (no server-side row stash)."""
    fields = ["individualId"] + s["fields"]
    cols = detect_columns(rows)
    hid = "".join("<input type='hidden' name='%s' value='%s'>" % (esc(k), esc(v))
                  for k, v in hidden.items())
    head = "".join("<th>" + esc(c) + "</th>" for c in cols)
    sample_rows = ""
    for r in rows[:3]:
        sample_rows += "<tr>" + "".join("<td>" + esc(r.get(c, "")) + "</td>" for c in cols) + "</tr>"
    sample = ("<table><thead><tr>" + head + "</tr></thead><tbody>" + sample_rows + "</tbody></table>")
    maprows = ""
    for f in fields:
        opts = "<option value=''>— none —</option>"
        for c in cols:
            sel = " selected" if c == f else ""
            opts += "<option value='%s'%s>%s</option>" % (esc(c), sel, esc(c))
        req = "<span class='req'> *</span>" if f == "individualId" else ""
        maprows += ("<div class='fld'><label>" + esc(f) + req + "</label>"
                    "<input type='hidden' name='mfield' value='" + esc(f) + "'>"
                    "<select name='mcol'>" + opts + "</select></div>")
    return ("<p><a href='/credential/" + esc(entity) + "'>&larr; back</a></p>"
            "<h2>" + esc(s["name"]) + " &mdash; map columns → fields</h2>"
            "<p class='meta'><b>" + str(len(rows)) + "</b> row(s) fetched. Map each entity field to a "
            "source column (defaults to an exact-name match). <code>individualId</code> is required.</p>"
            + sample
            + "<form class='box' method='post' action='" + esc(action) + "'>" + hid
            + "<div class='grid'>" + maprows + "</div>"
            "<div style='margin-top:.8rem'><button type='submit'>Import " + str(len(rows))
            + " record(s)</button></div></form>")


def _import_step(s, entity, action, rows, form, hidden):
    """No mapping in the form -> render the mapping step; otherwise apply it."""
    if "mfield" not in form:
        return page(s["name"], _mapping_page(s, entity, action, rows, hidden))
    mfields = form.getlist("mfield")
    mcols = form.getlist("mcol")
    mapping = {}
    for i, f in enumerate(mfields):
        c = mcols[i] if i < len(mcols) else ""
        if f and c:
            mapping[f] = c
    msg, cls = _apply_mapped_rows(entity, rows, mapping)
    return page(s["name"], credential_body(s, message=msg, msg_class=cls))


# ----------------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------------
CSS = """<style>
:root{--ink:#1a1a1a;--mute:#777;--line:#e3e3e3;--bg:#fafafa;--accent:#2b6cb0;--ok:#2f855a;--warn:#b7791f;--err:#c0392b}
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;color:var(--ink)}
header{padding:1.2rem 1.5rem;border-bottom:1px solid var(--line);background:var(--bg)}
h1{font-size:1.25rem;margin:0 0 .2rem}h2{font-size:1.05rem;margin:1.4rem 0 .6rem}
.sub{color:var(--mute);font-size:.85rem}
.links{margin-top:.6rem;font-size:.82rem}.links a{color:var(--accent);text-decoration:none;margin-right:1.1rem}
main{padding:1.3rem 1.5rem;max-width:1100px}
.card{border:1px solid var(--line);border-radius:10px;padding:1rem 1.1rem;margin-bottom:1rem;background:#fff}
.card h3{margin:0 0 .3rem;font-size:1rem}
.meta{color:var(--mute);font-size:.8rem;margin:.15rem 0}
.pill{display:inline-block;font-size:.7rem;padding:.12rem .5rem;border-radius:999px;font-weight:600}
.pill.yes{background:#e6f4ea;color:var(--ok)}.pill.no{background:#fdecea;color:var(--err)}
.fieldlist code{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:.06rem .35rem;font-size:.78rem;margin-right:.3rem}
a.btn,button{padding:.5rem .9rem;border:0;border-radius:6px;background:var(--accent);color:#fff;cursor:pointer;font-size:.88rem;text-decoration:none;display:inline-block}
button.ghost,a.btn.ghost{background:#ececec;color:#333}
table{width:100%;border-collapse:collapse;font-size:.84rem;margin-top:.4rem}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mute);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.03em}
td.key{font-family:ui-monospace,monospace;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:.8rem}
.fld label{display:block;font-size:.7rem;color:var(--mute);margin-bottom:.2rem;text-transform:uppercase}
.fld input{width:100%;padding:.5rem;border:1px solid var(--line);border-radius:6px;font-size:.9rem}
.req{color:var(--err)}
.msg{margin:.4rem 0 1rem;padding:.6rem .9rem;border-radius:8px;font-size:.86rem}
.msg.ok{background:#e6f4ea;color:var(--ok);border:1px solid #bfe3c9}
.msg.warn{background:#fff8e6;color:var(--warn);border:1px solid #f0e0b0}
.msg.err{background:#fdecea;color:var(--err);border:1px solid #f3c9c2}
form.box{margin:.4rem 0 1rem;padding:1rem;border:1px solid var(--line);border-radius:10px;background:var(--bg)}
.imp{margin-top:1rem;font-size:.85rem}.imp input[type=file]{font-size:.85rem}
</style>"""


# Landing-page description block — explains what this console is and how it
# links into verifiably's Inji credential flow. Rendered at the top of GET /.
HOME_DESC = (
    "<div class='card' style='border-left:3px solid var(--accent)'>"
    "<h3 style='margin-bottom:.45rem'>Registry Admin &mdash; the data-source tier for verifiably&rsquo;s Inji credential flow</h3>"
    "<p class='meta' style='line-height:1.5;font-size:.86rem;color:var(--ink)'>"
    "Issuers define credentials in <b>verifiably</b>; here you populate the authoritative "
    "registry (<b>Sunbird RC</b>) those credentials draw from. When a holder signs up via "
    "<b>eSignet</b> and claims a credential, verifiably auto-pulls their data from this "
    "registry by their <b>Individual ID</b> and issues it into the credential. "
    "One Sunbird entity per credential type &mdash; enter records keyed by Individual ID, "
    "or bulk-import CSV."
    "</p></div>"
)


def page(title, body):
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>" + esc(title) + "</title>" + CSS + "</head><body>"
            "<header><h1>Registries Admin Console</h1>"
            "<div class='sub'>Registrar &middot; data-population tier &mdash; one Sunbird RC entity per verifiably credential, holder records keyed by eSignet Individual ID</div>"
            "<div class='links'><a href='/'>&larr; All credentials</a>"
            "<a href='/health'>health</a></div></header>"
            "<main>" + body + "</main></body></html>")


def home_body():
    try:
        schemas = fetch_schemas()
    except Exception as e:  # noqa: BLE001
        return ("<div class='msg err'>Could not reach verifiably schemas at <code>"
                + esc(VERIFIABLY_SCHEMAS_URL) + "</code>: " + esc(str(e)) + "</div>")
    registered = list_registered_entities()
    if not schemas:
        return "<div class='msg warn'>No <b>custom</b> credential schemas found in verifiably.</div>"
    out = ["<p class='meta'>" + str(len(schemas)) + " custom credential schema(s) from <code>"
           + esc(VERIFIABLY_SCHEMAS_URL) + "</code>. Sunbird: <code>" + esc(SUNBIRD_URL) + "</code></p>"]
    for s in schemas:
        exists = s["entity"] in registered
        pill = ("<span class='pill yes'>entity registered</span>" if exists
                else "<span class='pill no'>not yet registered</span>")
        flds = "".join("<code>" + esc(f) + "</code>" for f in s["fields"]) or "<i>(none)</i>"
        out.append(
            "<div class='card'><h3>" + esc(s["name"]) + " &nbsp;" + pill + "</h3>"
            "<div class='meta'>Issuer: " + esc(s["issuer"] or "—")
            + " &middot; Standard: " + esc(s["std"] or "—") + "</div>"
            "<div class='meta'>Sunbird entity: <code>" + esc(s["entity"]) + "</code></div>"
            "<div class='meta fieldlist'>Fields: " + flds + "</div>"
            "<div style='margin-top:.7rem'><a class='btn' href='/credential/" + esc(s["entity"]) + "'>Manage &rarr;</a></div>"
            "</div>")
    return "".join(out)


def credential_body(s, message="", msg_class="", ensure_note=""):
    entity = s["entity"]
    fields = s["fields"]
    msg_html = ("<div class='msg " + msg_class + "'>" + message + "</div>") if message else ""
    if ensure_note:
        msg_html = ("<div class='msg ok'>Sunbird entity <code>" + esc(entity)
                    + "</code>: " + esc(ensure_note) + "</div>") + msg_html

    inputs = ("<div class='fld'><label>Individual ID <span class='req'>*</span></label>"
              "<input name='individualId' required placeholder='eSignet Individual ID'></div>")
    for f in fields:
        inputs += ("<div class='fld'><label>" + esc(f) + "</label>"
                   "<input name='" + esc(f) + "'></div>")

    form = ("<form class='box' method='post' action='/credential/" + esc(entity) + "'>"
            "<div class='grid'>" + inputs + "</div>"
            "<div style='margin-top:.8rem'><button type='submit'>Create record</button></div>"
            "</form>")

    imp = ("<form class='box imp' method='post' action='/credential/" + esc(entity)
           + "/import' enctype='multipart/form-data'>"
           "<b>Bulk import (CSV)</b> &mdash; header row must be <code>individualId,"
           + ",".join(esc(f) for f in fields) + "</code><br><br>"
           "<input type='file' name='file' accept='.csv,text/csv' required> "
           "<button type='submit'>Import CSV</button></form>")

    _inp = "style='width:100%;padding:.4rem;margin:.25rem 0;border:1px solid var(--line);border-radius:3px'"
    api = ("<form class='box' method='post' action='/credential/" + esc(entity) + "/import-api'>"
           "<b>From a JSON API</b> &mdash; GET returns an array (or {rows|data|items|results}); you map columns next."
           "<input name='api_url' required placeholder='https://host/path/citizens' " + _inp + ">"
           "<input name='api_auth' placeholder='Authorization header (optional)' " + _inp + ">"
           "<input name='api_limit' type='number' min='0' value='0' placeholder='row limit (0 = all)' " + _inp + ">"
           "<button type='submit'>Fetch &amp; map →</button></form>")
    db = ("<form class='box' method='post' action='/credential/" + esc(entity) + "/import-db'>"
          "<b>From a database</b> &mdash; a Postgres SELECT (read-only); you map columns next."
          "<input name='db_conn' required placeholder='postgres://user:pass@host:5432/db?sslmode=disable' " + _inp + ">"
          "<textarea name='db_query' required rows='3' placeholder='SELECT national_id, full_name, dob FROM citizens' " + _inp + "></textarea>"
          "<button type='submit'>Fetch &amp; map →</button></form>")
    reg = ("<form class='box' method='post' action='/credential/" + esc(entity) + "/import-registry'>"
           "<b>From another Sunbird RC registry</b> &mdash; pulls every record of an entity; you map columns next."
           "<input name='reg_url' required placeholder='https://other-registry:8081' " + _inp + ">"
           "<input name='reg_entity' required placeholder='entity name' " + _inp + ">"
           "<button type='submit'>Fetch &amp; map →</button></form>")

    # recent records
    recs = search_records(entity, {})
    cols = ["individualId"] + fields + ["osid"]
    head = "".join("<th>" + esc(c) + "</th>" for c in cols)
    body_rows = ""
    for r in recs[-10:][::-1]:
        body_rows += "<tr>" + "".join(
            "<td" + (" class='key'" if c == "individualId" else "") + ">" + esc(r.get(c, "")) + "</td>"
            for c in cols) + "</tr>"
    if not body_rows:
        body_rows = "<tr><td colspan='" + str(len(cols)) + "' class='meta'>No records yet.</td></tr>"
    table = ("<h2>Recent records <span class='meta'>(" + str(len(recs)) + " total)</span></h2>"
             "<table><thead><tr>" + head + "</tr></thead><tbody>" + body_rows + "</tbody></table>")

    return ("<h2>" + esc(s["name"]) + "</h2>"
            "<p class='meta'>Sunbird entity <code>" + esc(entity) + "</code> &middot; issuer "
            + esc(s["issuer"] or "—") + "</p>" + msg_html
            + "<h2>Register a holder record</h2>" + form + imp
            + "<h2>Bulk from a data source</h2>" + api + db + reg + table)


# ----------------------------------------------------------------------------
# routes
# ----------------------------------------------------------------------------
@app.get("/health", response_class=HTMLResponse)
def health():
    return HTMLResponse('{"status":"ok"}', media_type="application/json")


@app.get("/", response_class=HTMLResponse)
def home():
    return page("Registries Admin Console", HOME_DESC + home_body())


@app.get("/credential/{entity}", response_class=HTMLResponse)
def credential_get(entity: str):
    s = find_schema(entity)
    if not s:
        return HTMLResponse(page("Not found",
            "<div class='msg err'>No custom credential maps to entity <code>"
            + esc(entity) + "</code>.</div>"), status_code=404)
    ok, note = ensure_entity(entity, s["fields"])
    if not ok:
        return HTMLResponse(page(s["name"],
            credential_body(s, message="Could not make the Sunbird entity searchable: "
                            + esc(note), msg_class="err")))
    return page(s["name"], credential_body(s, ensure_note=note))


@app.post("/credential/{entity}", response_class=HTMLResponse)
async def credential_post(entity: str, request: Request):
    s = find_schema(entity)
    if not s:
        return HTMLResponse(page("Not found",
            "<div class='msg err'>Unknown entity <code>" + esc(entity) + "</code>.</div>"),
            status_code=404)
    ok, note = ensure_entity(entity, s["fields"])
    if not ok:
        return HTMLResponse(page(s["name"],
            credential_body(s, message="Entity not ready: " + esc(note), msg_class="err")))

    form = await request.form()
    ind = (form.get("individualId") or "").strip()
    if not ind:
        return HTMLResponse(page(s["name"],
            credential_body(s, message="Individual ID is required.", msg_class="err")))
    body = {"individualId": ind}
    for f in s["fields"]:
        v = form.get(f)
        if v is not None and str(v).strip() != "":
            body[f] = str(v).strip()

    st, txt = create_record(entity, body)
    if st in (200, 201):
        osid = parse_osid(entity, txt)
        msg = ("Created record for Individual ID <code>" + esc(ind) + "</code>. osid = <code>"
               + esc(osid or "?") + "</code>")
        cls = "ok"
    elif is_duplicate(txt):
        msg = "A record with Individual ID <code>" + esc(ind) + "</code> already exists (duplicate)."
        cls = "warn"
    else:
        msg = "Create failed (http " + esc(st) + "): " + esc(txt[:300])
        cls = "err"
    return page(s["name"], credential_body(s, message=msg, msg_class=cls))


@app.post("/credential/{entity}/import", response_class=HTMLResponse)
async def credential_import(entity: str, file: UploadFile = File(...)):
    s = find_schema(entity)
    if not s:
        return HTMLResponse(page("Not found",
            "<div class='msg err'>Unknown entity <code>" + esc(entity) + "</code>.</div>"),
            status_code=404)
    ok, note = ensure_entity(entity, s["fields"])
    if not ok:
        return HTMLResponse(page(s["name"],
            credential_body(s, message="Entity not ready: " + esc(note), msg_class="err")))

    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except Exception:  # noqa: BLE001
        text = raw.decode("latin-1", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    okc = dup = fail = 0
    errs = []
    for row in reader:
        ind = (row.get("individualId") or "").strip()
        if not ind:
            fail += 1
            continue
        body = {"individualId": ind}
        for f in s["fields"]:
            if f in row and row.get(f) is not None and str(row[f]).strip() != "":
                body[f] = str(row[f]).strip()
        st, txt = create_record(entity, body)
        if st in (200, 201):
            okc += 1
        elif is_duplicate(txt):
            dup += 1
        else:
            fail += 1
            if len(errs) < 3:
                errs.append("http " + str(st) + ": " + txt[:80])
        time.sleep(0.3)
    detail = (" &middot; sample errors: " + esc("; ".join(errs))) if errs else ""
    msg = ("CSV import complete: <b>" + str(okc) + "</b> created, <b>" + str(dup)
           + "</b> duplicates, <b>" + str(fail) + "</b> failed." + detail)
    cls = "ok" if fail == 0 else ("warn" if okc or dup else "err")
    return page(s["name"], credential_body(s, message=msg, msg_class=cls))


def _ready(entity):
    """Resolve the schema + ensure the Sunbird entity is searchable; returns
    (schema, error_html_or_None)."""
    s = find_schema(entity)
    if not s:
        return None, page("Not found", "<div class='msg err'>Unknown entity <code>" + esc(entity) + "</code>.</div>")
    ok, note = ensure_entity(entity, s["fields"])
    if not ok:
        return s, page(s["name"], credential_body(s, message="Entity not ready: " + esc(note), msg_class="err"))
    return s, None


@app.post("/credential/{entity}/import-api", response_class=HTMLResponse)
async def import_api(entity: str, request: Request):
    s, err = _ready(entity)
    if err:
        return HTMLResponse(err)
    form = await request.form()
    url = (form.get("api_url") or "").strip()
    auth = (form.get("api_auth") or "").strip()
    limit = (form.get("api_limit") or "").strip()
    if not url:
        return page(s["name"], credential_body(s, message="API URL is required.", msg_class="err"))
    try:
        rows = fetch_json_rows(url, auth, limit)
    except Exception as e:  # noqa: BLE001
        return page(s["name"], credential_body(s, message="API fetch failed: " + esc(e), msg_class="err"))
    if not rows:
        return page(s["name"], credential_body(s, message="No rows returned from the API.", msg_class="warn"))
    return _import_step(s, entity, "/credential/" + entity + "/import-api", rows, form,
                        {"api_url": url, "api_auth": auth, "api_limit": limit})


@app.post("/credential/{entity}/import-db", response_class=HTMLResponse)
async def import_db(entity: str, request: Request):
    s, err = _ready(entity)
    if err:
        return HTMLResponse(err)
    form = await request.form()
    conn = (form.get("db_conn") or "").strip()
    query = (form.get("db_query") or "").strip()
    if not conn or not query:
        return page(s["name"], credential_body(s, message="Connection string and SELECT query are both required.", msg_class="err"))
    try:
        rows = query_db_rows(conn, query)
    except Exception as e:  # noqa: BLE001
        return page(s["name"], credential_body(s, message="Database query failed: " + esc(e), msg_class="err"))
    if not rows:
        return page(s["name"], credential_body(s, message="Query returned no rows.", msg_class="warn"))
    return _import_step(s, entity, "/credential/" + entity + "/import-db", rows, form,
                        {"db_conn": conn, "db_query": query})


@app.post("/credential/{entity}/import-registry", response_class=HTMLResponse)
async def import_registry(entity: str, request: Request):
    s, err = _ready(entity)
    if err:
        return HTMLResponse(err)
    form = await request.form()
    url = (form.get("reg_url") or "").strip()
    ent = (form.get("reg_entity") or "").strip()
    if not url or not ent:
        return page(s["name"], credential_body(s, message="Registry URL and entity are both required.", msg_class="err"))
    try:
        rows = fetch_registry_rows(url, ent)
    except Exception as e:  # noqa: BLE001
        return page(s["name"], credential_body(s, message="Registry fetch failed: " + esc(e), msg_class="err"))
    if not rows:
        return page(s["name"], credential_body(s, message="No records found in that registry entity.", msg_class="warn"))
    return _import_step(s, entity, "/credential/" + entity + "/import-registry", rows, form,
                        {"reg_url": url, "reg_entity": ent})
