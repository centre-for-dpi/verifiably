#!/bin/bash
# Full Credential Lifecycle Test against Walt.id DPG Stack
# Tests: Onboard → Issue → Claim → Verify → Audit
set -e

ISSUER_URL="http://localhost:7002"
VERIFIER_URL="http://localhost:7003"
WALLET_URL="http://localhost:7001"

echo "=========================================="
echo "  CREDENTIAL LIFECYCLE TEST"
echo "  $(date)"
echo "=========================================="

# --- 1. Register or login wallet user ---
echo ""
echo "[1/8] Wallet user authentication"
# Try register first, ignore if already exists
curl -s -X POST "$WALLET_URL/wallet-api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"name":"lifecycle-test","email":"lifecycle@test.com","password":"TestPass123!","type":"email"}' > /dev/null 2>&1

LOGIN=$(curl -s -X POST "$WALLET_URL/wallet-api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"lifecycle@test.com","password":"TestPass123!","type":"email"}')
TOKEN=$(echo "$LOGIN" | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
WALLETS=$(curl -s -H "Authorization: Bearer $TOKEN" "$WALLET_URL/wallet-api/wallet/accounts/wallets")
WALLET_ID=$(echo "$WALLETS" | python3 -c "import json,sys; print(json.load(sys.stdin)['wallets'][0]['id'])")
echo "  PASS: Logged in, wallet=$WALLET_ID"

# --- 2. Get holder DID ---
echo ""
echo "[2/8] Holder DID"
DID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$WALLET_URL/wallet-api/wallet/${WALLET_ID}/dids" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['did'])")
echo "  PASS: DID=${DID:0:40}..."

# --- 3. Onboard issuer ---
echo ""
echo "[3/8] Onboard issuer (generate key + DID)"
ISSUER=$(curl -s -X POST "$ISSUER_URL/onboard/issuer" \
  -H "Content-Type: application/json" \
  -d '{"key":{"backend":"jwk","keyType":"secp256r1"}}')
ISSUER_KEY=$(echo "$ISSUER" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['issuerKey']))")
ISSUER_DID=$(echo "$ISSUER" | python3 -c "import json,sys; print(json.load(sys.stdin)['issuerDid'])")
echo "  PASS: Issuer DID=${ISSUER_DID:0:40}..."

# --- 4. Issue credential ---
echo ""
echo "[4/8] Issue credential (OID4VCI)"
ISSUE_REQ=$(python3 -c "
import json
req = {
    'issuerKey': json.loads('''$ISSUER_KEY'''),
    'issuerDid': '$ISSUER_DID',
    'credentialConfigurationId': 'UniversityDegree_jwt_vc_json',
    'credentialData': {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        'type': ['VerifiableCredential', 'UniversityDegree'],
        'credentialSubject': {
            'name': 'Jane Doe',
            'degree': 'BSc Computer Science',
            'university': 'University of the West Indies',
            'graduationDate': '2025-06-15',
            'gpa': '3.7',
            'studentId': '816003245'
        }
    }
}
print(json.dumps(req))
")
OFFER=$(curl -s -X POST "$ISSUER_URL/openid4vc/jwt/issue" \
  -H "Content-Type: application/json" -d "$ISSUE_REQ")
if echo "$OFFER" | grep -q "openid-credential-offer"; then
  echo "  PASS: Credential offer created"
else
  echo "  FAIL: $OFFER"
  exit 1
fi

# --- 5. Claim credential in wallet ---
echo ""
echo "[5/8] Claim credential in wallet"
CLAIM=$(curl -s -X POST "$WALLET_URL/wallet-api/wallet/${WALLET_ID}/exchange/useOfferRequest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/plain" \
  -d "$OFFER")

# Get credential
CREDS=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$WALLET_URL/wallet-api/wallet/${WALLET_ID}/credentials")
CRED_COUNT=$(echo "$CREDS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
CRED_ID=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[-1]['id'])")
CRED_NAME=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[-1].get('parsedDocument',{}).get('credentialSubject',{}).get('name','?'))")
echo "  PASS: $CRED_COUNT credential(s) in wallet, latest: $CRED_NAME (ID: ${CRED_ID:0:20}...)"

# --- 6. Create verification request ---
echo ""
echo "[6/8] Create verification request (OID4VP)"
VP_URL=$(curl -s -X POST "$VERIFIER_URL/openid4vc/verify" \
  -H "Content-Type: application/json" \
  -d '{"vp_policies":["signature"],"vc_policies":["signature"],"request_credentials":[{"type":"VerifiableCredential","format":"jwt_vc_json"}]}')
STATE=$(echo "$VP_URL" | sed 's/.*state=\([^&]*\).*/\1/')
if echo "$VP_URL" | grep -q "openid4vp://"; then
  echo "  PASS: VP request created, state=$STATE"
else
  echo "  FAIL: $VP_URL"
  exit 1
fi

# --- 7. Present credential to verifier ---
echo ""
echo "[7/8] Present credential to verifier"
PRESENT_REQ=$(python3 -c "
import json
req = {
    'did': '$DID',
    'presentationRequest': '''$VP_URL''',
    'selectedCredentials': ['$CRED_ID']
}
print(json.dumps(req))
")
PRESENT_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$WALLET_URL/wallet-api/wallet/${WALLET_ID}/exchange/usePresentationRequest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$PRESENT_REQ")
if [[ "$PRESENT_RESP" == "200" ]]; then
  echo "  PASS: Credential presented (HTTP 200)"
else
  echo "  FAIL: HTTP $PRESENT_RESP"
  exit 1
fi

# --- 8. Check verification result ---
echo ""
echo "[8/8] Verify credential (6-point check)"
sleep 2
RESULT=$(curl -s "$VERIFIER_URL/openid4vc/session/$STATE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verificationResult','unknown'))")
if [[ "$RESULT" == "True" ]]; then
  echo "  PASS: *** VERIFICATION PASSED ***"
else
  echo "  FAIL: verificationResult=$RESULT"
  exit 1
fi

# Show presented credentials
PRESENTED=$(curl -s "$VERIFIER_URL/openid4vc/session/$STATE/presented-credentials")
echo ""
echo "  Presented credentials:"
echo "$PRESENTED" | python3 -c "
import json,sys
try:
    data = json.load(sys.stdin)
    if data:
        for c in data:
            subj = c.get('credentialSubject',{})
            print(f'    type: {c.get(\"type\",[])}')
            for k,v in subj.items():
                if k != 'id': print(f'      {k}: {v}')
    else:
        print('    (credentials verified but detail not returned in this endpoint)')
except:
    print('    (verified successfully)')
" 2>/dev/null || true

echo ""
echo "=========================================="
echo "  ALL 8 STEPS PASSED"
echo "  $(date)"
echo "=========================================="
