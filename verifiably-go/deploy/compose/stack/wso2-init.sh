#!/bin/bash
# Waits for WSO2 IS to be ready, then creates the OIDC application
# and writes the client_id to a shared file for the Go app to read.
# All values come from environment variables with sensible defaults.

set -e

WSO2_URL="${WSO2_URL:-https://localhost:${WSO2_PORT:-9443}}"
WSO2_ADMIN="${WSO2_ADMIN_USER:-admin}:${WSO2_ADMIN_PASSWORD:-admin}"
APP_NAME="${WSO2_APP_NAME:-vcplatform}"
CALLBACK_URL="${APP_BASE_URL:-http://localhost:${APP_PORT:-8080}}/auth/callback"
OUTPUT_FILE="${WSO2_CLIENT_ID_FILE:-/tmp/wso2-client-id}"

echo "[wso2-init] WSO2 URL: $WSO2_URL"
echo "[wso2-init] Callback: $CALLBACK_URL"
echo "[wso2-init] Output: $OUTPUT_FILE"

echo "[wso2-init] Waiting for WSO2 Identity Server..."
for i in $(seq 1 60); do
  if curl -sk "$WSO2_URL/carbon/admin/login.jsp" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200"; then
    echo "[wso2-init] WSO2 is ready."
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "[wso2-init] ERROR: WSO2 did not start within 5 minutes"
    exit 1
  fi
  sleep 5
done

# Check if app already exists
EXISTING=$(curl -sk "$WSO2_URL/api/server/v1/applications?filter=name+eq+$APP_NAME" \
  -u "$WSO2_ADMIN" 2>/dev/null)
EXISTING_ID=$(echo "$EXISTING" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    apps=d.get('applications',[])
    if apps: print(apps[0]['id'])
except: pass
" 2>/dev/null)

if [[ -n "$EXISTING_ID" ]]; then
  echo "[wso2-init] App '$APP_NAME' already exists (id=$EXISTING_ID)"
else
  echo "[wso2-init] Creating app '$APP_NAME'..."
  curl -sk -X POST "$WSO2_URL/api/server/v1/applications" \
    -u "$WSO2_ADMIN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"$APP_NAME\",
      \"description\": \"VC Platform OIDC Client\",
      \"inboundProtocolConfiguration\": {
        \"oidc\": {
          \"grantTypes\": [\"authorization_code\"],
          \"callbackURLs\": [\"$CALLBACK_URL\"],
          \"publicClient\": true,
          \"allowedOrigins\": [\"${APP_BASE_URL:-http://localhost:${APP_PORT:-8080}}\"]
        }
      },
      \"authenticationSequence\": {\"type\": \"DEFAULT\"},
      \"claimConfiguration\": {
        \"requestedClaims\": [
          {\"claim\": {\"uri\": \"http://wso2.org/claims/emailaddress\"}, \"mandatory\": false},
          {\"claim\": {\"uri\": \"http://wso2.org/claims/fullname\"}, \"mandatory\": false}
        ]
      }
    }" -o /dev/null 2>/dev/null

  sleep 2
  EXISTING=$(curl -sk "$WSO2_URL/api/server/v1/applications?filter=name+eq+$APP_NAME" \
    -u "$WSO2_ADMIN" 2>/dev/null)
  EXISTING_ID=$(echo "$EXISTING" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    apps=d.get('applications',[])
    if apps: print(apps[0]['id'])
except: pass
" 2>/dev/null)
fi

# Get the client_id
CLIENT_ID=$(curl -sk "$WSO2_URL/api/server/v1/applications/$EXISTING_ID/inbound-protocols/oidc" \
  -u "$WSO2_ADMIN" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('clientId',''))" 2>/dev/null)

if [[ -n "$CLIENT_ID" ]]; then
  echo "[wso2-init] WSO2 client_id: $CLIENT_ID"
  echo "$CLIENT_ID" > "$OUTPUT_FILE"
  echo "[wso2-init] Written to $OUTPUT_FILE"
else
  echo "[wso2-init] ERROR: Could not get client_id"
  exit 1
fi

# Enable self-registration via the management console's SCIM config endpoint
echo "[wso2-init] Enabling self-registration..."
# WSO2 7.0 default already has self-registration enabled in some distributions.
# Check and enable if needed.
SR_STATUS=$(curl -sk "$WSO2_URL/api/server/v1/identity-governance/VXNlciBPbmJvYXJkaW5n/connectors/c2VsZi1zaWduLXVw" \
  -u "$WSO2_ADMIN" 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    for p in d.get('properties',[]):
        if p.get('name')=='SelfRegistration.Enable': print(p['value'])
except: print('unknown')
" 2>/dev/null)

if [[ "$SR_STATUS" == "true" ]]; then
  echo "[wso2-init] Self-registration already enabled"
else
  echo "[wso2-init] Self-registration is '$SR_STATUS' — WSO2 7.0 requires Carbon console to enable."
  echo "[wso2-init] To enable manually: login at $WSO2_URL/carbon → Identity → User Self Registration → Enable"
fi

echo "[wso2-init] Done."
