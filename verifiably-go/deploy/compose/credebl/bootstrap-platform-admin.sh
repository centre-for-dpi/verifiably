#!/bin/sh
set -eu

: "${KEYCLOAK_ADMIN_USER:?Missing KEYCLOAK_ADMIN_USER}"
: "${KEYCLOAK_ADMIN_PASSWORD:?Missing KEYCLOAK_ADMIN_PASSWORD}"
: "${KEYCLOAK_REALM:?Missing KEYCLOAK_REALM}"
: "${PLATFORM_ADMIN_EMAIL:?Missing PLATFORM_ADMIN_EMAIL}"
: "${POSTGRES_USER:?Missing POSTGRES_USER}"
: "${POSTGRES_PASSWORD:?Missing POSTGRES_PASSWORD}"
: "${POSTGRES_DB:?Missing POSTGRES_DB}"
: "${PLATFORM_WEB_URL:?Missing PLATFORM_WEB_URL}"

KEYCLOAK_BASE_URL="${KEYCLOAK_ADMIN_URL:-http://keycloak:8080}"
KEYCLOAK_MASTER_REALM="${KEYCLOAK_MASTER_REALM:-master}"
PLATFORM_ADMIN_INITIAL_PASSWORD="${PLATFORM_ADMIN_INITIAL_PASSWORD:-changeme}"
PLATFORM_HOST="${VPS_IP:-}"

if [ -z "$PLATFORM_HOST" ]; then
  PLATFORM_HOST="$PLATFORM_WEB_URL"
  PLATFORM_HOST="${PLATFORM_HOST#http://}"
  PLATFORM_HOST="${PLATFORM_HOST#https://}"
  PLATFORM_HOST="${PLATFORM_HOST%%/*}"
  PLATFORM_HOST="${PLATFORM_HOST%%:*}"
fi

wait_for() {
  name="$1"
  shift
  attempts=0
  until "$@" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 60 ]; then
      echo "Timed out waiting for $name" >&2
      return 1
    fi
    sleep 2
  done
}

echo "==> Waiting for Postgres"
export PGPASSWORD="$POSTGRES_PASSWORD"
wait_for "Postgres" psql -h credebl-postgres -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc 'SELECT 1'

echo "==> Waiting for Keycloak"
wait_for "Keycloak" curl -fsS "$KEYCLOAK_BASE_URL/realms/$KEYCLOAK_MASTER_REALM/.well-known/openid-configuration"

echo "==> Requesting Keycloak admin token"
TOKEN="$({
  curl -fsS -X POST "$KEYCLOAK_BASE_URL/realms/$KEYCLOAK_MASTER_REALM/protocol/openid-connect/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_id=admin-cli' \
    --data-urlencode "username=$KEYCLOAK_ADMIN_USER" \
    --data-urlencode "password=$KEYCLOAK_ADMIN_PASSWORD";
} | jq -r '.access_token // empty')"

if [ -z "$TOKEN" ]; then
  echo "Failed to obtain Keycloak admin token" >&2
  exit 1
fi

lookup_user() {
  curl -fsS -G "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/users" \
    -H "Authorization: Bearer $TOKEN" \
    --data-urlencode "email=$PLATFORM_ADMIN_EMAIL" \
    --data-urlencode 'exact=true'
}

USER_JSON="$(lookup_user)"
KC_USER_ID="$(printf '%s' "$USER_JSON" | jq -r '.[0].id // empty')"

if [ -z "$KC_USER_ID" ]; then
  echo "==> Platform user not found in Keycloak; creating it"
  CREATE_STATUS="$(curl -sS -o /tmp/platform-admin-create.out -w '%{http_code}' \
    -X POST "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/users" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc \
      --arg username "$PLATFORM_ADMIN_EMAIL" \
      --arg email "$PLATFORM_ADMIN_EMAIL" \
      '{username:$username,email:$email,enabled:true,emailVerified:true,firstName:"Platform",lastName:"Admin"}')")"

  if [ "$CREATE_STATUS" != "201" ] && [ "$CREATE_STATUS" != "409" ]; then
    echo "Keycloak user creation failed (HTTP $CREATE_STATUS):" >&2
    cat /tmp/platform-admin-create.out >&2
    exit 1
  fi

  USER_JSON="$(lookup_user)"
  KC_USER_ID="$(printf '%s' "$USER_JSON" | jq -r '.[0].id // empty')"
fi

if [ -z "$KC_USER_ID" ]; then
  echo "Could not resolve the Keycloak user id for $PLATFORM_ADMIN_EMAIL" >&2
  exit 1
fi

echo "==> Setting platform admin password"
curl -fsS -o /dev/null \
  -X PUT "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/users/$KC_USER_ID/reset-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg value "$PLATFORM_ADMIN_INITIAL_PASSWORD" '{type:"password",temporary:false,value:$value}')"

echo "==> Ensuring Keycloak realm role 'platform-admin' is mapped"
ROLE_STATUS="$(curl -sS -o /tmp/platform-admin-role.out -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/roles/platform-admin")"
if [ "$ROLE_STATUS" = "200" ]; then
  ROLE_PAYLOAD="$(jq -c '[{id:.id,name:.name}]' /tmp/platform-admin-role.out)"
  curl -fsS -o /dev/null \
    -X POST "$KEYCLOAK_BASE_URL/admin/realms/$KEYCLOAK_REALM/users/$KC_USER_ID/role-mappings/realm" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$ROLE_PAYLOAD" || true
fi

echo "==> Linking the Keycloak user id in Postgres"
psql -h credebl-postgres -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -c "UPDATE \"user\" SET \"keycloakUserId\"='${KC_USER_ID}' WHERE email='${PLATFORM_ADMIN_EMAIL}';"

echo "==> Ensuring 'owner' role for platform admin in 'Platform-admin' organization"
psql -h credebl-postgres -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -c "INSERT INTO user_org_roles (id, \"userId\", \"orgId\", \"orgRoleId\")
      SELECT gen_random_uuid(), u.id, o.id, r.id
      FROM \"user\" u, organisation o, org_roles r
      WHERE u.email='${PLATFORM_ADMIN_EMAIL}'
        AND o.name='Platform-admin'
        AND r.name='owner'
        AND NOT EXISTS (
          SELECT 1 FROM user_org_roles
          WHERE \"userId\"=u.id AND \"orgId\"=o.id AND \"orgRoleId\"=r.id
        );"

echo "==> Ensuring DEFAULT_USER role is assigned in user_role_mapping"
psql -h credebl-postgres -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -c "INSERT INTO user_role_mapping (id, \"userId\", \"userRoleId\")
      SELECT gen_random_uuid(), u.id, ur.id
      FROM \"user\" u, user_role ur
      WHERE u.email='${PLATFORM_ADMIN_EMAIL}'
        AND ur.role='DEFAULT_USER'
        AND NOT EXISTS (
          SELECT 1 FROM user_role_mapping
          WHERE \"userId\"=u.id AND \"userRoleId\"=ur.id
        );"

echo "==> Syncing platform configuration endpoints in Postgres"
psql -h credebl-postgres -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -c "UPDATE platform_config SET \"externalIp\"='${PLATFORM_HOST}', \"inboundEndpoint\"='${PLATFORM_HOST}', \"apiEndpoint\"='${PLATFORM_WEB_URL}';"

echo "==> Platform admin bootstrap sync completed"
echo "    Email:    $PLATFORM_ADMIN_EMAIL"
echo "    Password: $PLATFORM_ADMIN_INITIAL_PASSWORD"
