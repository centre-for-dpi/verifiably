#!/usr/bin/env python3
# E2E: inji PRE-AUTH delegated access, fully headless via verifiably's own
# conformant-proof holder (no external wallet). issue -> claim (server-side
# pre-auth) -> verify AUTHORIZED -> revoke -> verify DENIED.
import json, os, time, urllib.request, urllib.error

BASE = os.environ.get("BASE", "https://verifiably.in-labs.cdpi.dev")
KEY = os.environ["API_KEY"]
DPG = os.environ.get("DPG", "Inji Certify · Pre-Auth")
SUBJ_TYPE = os.environ.get("SUBJ_TYPE", "BirthCertificate")
DELEG_TYPE = os.environ.get("DELEG_TYPE", "DelegationPre")
NS = "urn:person:preauth-" + str(int(time.time()))

def api(method, path, body):
    req = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def fail(m):
    print("✗ FAIL:", m); raise SystemExit(1)

# 1. issue the pre-auth pair
st, iss = api("POST", "/api/v1/delegation/inji/preauth/issue",
    {"dpg": DPG, "subjectType": SUBJ_TYPE, "delegationType": DELEG_TYPE,
     "subjectRef": NS, "givenName": "Maria", "role": "Mother",
     "allowedAction": ["present", "consent:disclose"], "validUntil": "2033-03-10T00:00:00Z"})
if st != 201: fail(f"issue {st} {iss}")
o1, o2, idx = iss["subject"]["offerUri"], iss["delegation"]["offerUri"], iss["statusListIndex"]
pin = iss.get("pin", "")
print(f"• issued pre-auth pair; statusIdx={idx}{' pin='+pin if pin else ''}")

# 2. headless claim both offers (verifiably's conformant-proof holder)
st, cl = api("POST", "/api/v1/delegation/inji/preauth/claim", {"offers": [o1, o2], "txCode": pin})
if st != 200: fail(f"claim {st} {cl}")
creds = cl["credentials"]
print(f"• claimed {len(creds)} creds headlessly (sd-jwt lengths: {[len(c) for c in creds]})")

# 3. verify -> AUTHORIZED
st, v1 = api("POST", "/api/v1/delegation/verify/sdjwt", {"credentials": creds})
print("• verdict#1", json.dumps(v1))
d1 = (v1 or {}).get("delegation") or {}
if d1.get("Authorized") is not True: fail(f"expected AUTHORIZED, got {d1}")
print(f"• ✓ AUTHORIZED (linkage={d1['Linkage']} invocation={d1['Invocation']} capability={d1['Capability']} notRevoked={d1['NotRevoked']})")

# 4. revoke -> DENIED
st, rev = api("POST", "/api/v1/delegation/inji/revoke", {"index": idx})
print("• revoke ->", st, rev)
st, v2 = api("POST", "/api/v1/delegation/verify/sdjwt", {"credentials": creds})
print("• verdict#2", json.dumps(v2))
d2 = (v2 or {}).get("delegation") or {}
if d2.get("Authorized") is True: fail("expected DENIED after revoke")
print(f"• ✓ DENIED after revoke (reason: {d2.get('Reason')})")

print("\n✅ INJI PRE-AUTH DELEGATION E2E PASSED: issue -> headless claim -> AUTHORIZED -> revoke -> DENIED")
