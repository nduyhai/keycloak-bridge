#!/bin/sh
set -eu

KC_BIN="/opt/keycloak/bin/kcadm.sh"

KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak:8080}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

REALM="${REALM:-demo}"

# IdP (Bridge)
IDP_ALIAS="${IDP_ALIAS:-bridge}"
BRIDGE_PUBLIC_ISSUER="${BRIDGE_PUBLIC_ISSUER:-http://localhost:8081}"
BRIDGE_INTERNAL_ISSUER="${BRIDGE_INTERNAL_ISSUER:-http://bridge:8081}"
BRIDGE_CLIENT_ID="${BRIDGE_CLIENT_ID:-keycloak-broker}"
BRIDGE_CLIENT_SECRET="${BRIDGE_CLIENT_SECRET:-keycloak-broker-secret}"

# RP client (App -> Keycloak)
RP_CLIENT_ID="${RP_CLIENT_ID:-rp-client}"
RP_CLIENT_SECRET="${RP_CLIENT_SECRET:-rp-secret}"
RP_REDIRECT_URI="${RP_REDIRECT_URI:-http://localhost:8091/callback}"

echo "==> Waiting for Keycloak at ${KEYCLOAK_URL} ..."
i=0
until ${KC_BIN} config credentials \
  --server "${KEYCLOAK_URL}" \
  --realm master \
  --user "${KEYCLOAK_ADMIN}" \
  --password "${KEYCLOAK_ADMIN_PASSWORD}" >/dev/null 2>&1
do
  i=$((i+1))
  if [ "$i" -gt 80 ]; then
    echo "ERROR: Keycloak not ready after 80 tries"
    exit 1
  fi
  sleep 2
done
echo "==> Logged in"

# ---------- Realm ----------
if ${KC_BIN} get "realms/${REALM}" >/dev/null 2>&1; then
  echo "==> Realm ${REALM} exists"
else
  echo "==> Creating realm ${REALM}"
  ${KC_BIN} create realms -s "realm=${REALM}" -s "enabled=true" >/dev/null
fi

# ---------- RP Client ----------
get_client_id() {
  ${KC_BIN} get clients -r "${REALM}" -q "clientId=$1" --fields id --format csv \
    | tail -n 1 \
    | tr -d '\r"'
}

RP_UUID="$(get_client_id "${RP_CLIENT_ID}")"
if [ -n "${RP_UUID}" ]; then
  echo "==> RP client ${RP_CLIENT_ID} exists (id=${RP_UUID}), updating..."
  ${KC_BIN} update "clients/${RP_UUID}" -r "${REALM}" \
    -s "enabled=true" \
    -s "protocol=openid-connect" \
    -s "publicClient=false" \
    -s "standardFlowEnabled=true" \
    -s "directAccessGrantsEnabled=false" \
    -s "redirectUris=[\"${RP_REDIRECT_URI}\"]" >/dev/null
else
  echo "==> Creating RP client ${RP_CLIENT_ID}"
  ${KC_BIN} create clients -r "${REALM}" -i \
    -s "clientId=${RP_CLIENT_ID}" \
    -s "enabled=true" \
    -s "protocol=openid-connect" \
    -s "publicClient=false" \
    -s "standardFlowEnabled=true" \
    -s "directAccessGrantsEnabled=false" \
    -s "redirectUris=[\"${RP_REDIRECT_URI}\"]" >/dev/null
  RP_UUID="$(get_client_id "${RP_CLIENT_ID}")"
fi

echo "==> Setting RP secret"
${KC_BIN} update "clients/${RP_UUID}" -r "${REALM}" -s "secret=${RP_CLIENT_SECRET}" >/dev/null

# ---------- Identity Provider (Bridge OIDC) ----------
if ${KC_BIN} get "identity-provider/instances/${IDP_ALIAS}" -r "${REALM}" >/dev/null 2>&1; then
  echo "==> IdP ${IDP_ALIAS} exists, updating..."
  ${KC_BIN} update "identity-provider/instances/${IDP_ALIAS}" -r "${REALM}" \
    -s "enabled=true" \
    -s "providerId=oidc" \
    -s "config.clientId=${BRIDGE_CLIENT_ID}" \
    -s "config.clientSecret=${BRIDGE_CLIENT_SECRET}" \
    -s "config.authorizationUrl=${BRIDGE_PUBLIC_ISSUER}/oauth2/authorize" \
    -s "config.tokenUrl=${BRIDGE_INTERNAL_ISSUER}/oauth2/token" \
    -s "config.jwksUrl=${BRIDGE_INTERNAL_ISSUER}/oauth2/jwks" \
    -s "config.userInfoUrl=${BRIDGE_INTERNAL_ISSUER}/oauth2/userinfo" \
    -s "config.defaultScope=openid profile email" \
    -s "config.useJwksUrl=true" \
    -s "config.pkceEnabled=true" \
    -s "config.pkceMethod=S256" \
    -s "config.validateSignature=true" >/dev/null
else
  echo "==> Creating IdP ${IDP_ALIAS} -> ${BRIDGE_ISSUER}"
  ${KC_BIN} create identity-provider/instances -r "${REALM}" -i \
    -s "alias=${IDP_ALIAS}" \
    -s "enabled=true" \
    -s "providerId=oidc" \
    -s "config.clientId=${BRIDGE_CLIENT_ID}" \
    -s "config.clientSecret=${BRIDGE_CLIENT_SECRET}" \
     -s "config.authorizationUrl=${BRIDGE_PUBLIC_ISSUER}/oauth2/authorize" \
     -s "config.tokenUrl=${BRIDGE_INTERNAL_ISSUER}/oauth2/token" \
     -s "config.jwksUrl=${BRIDGE_INTERNAL_ISSUER}/oauth2/jwks" \
     -s "config.userInfoUrl=${BRIDGE_INTERNAL_ISSUER}/oauth2/userinfo" \
    -s "config.defaultScope=openid profile email" \
    -s "config.useJwksUrl=true" \
    -s "config.pkceEnabled=true" \
    -s "config.pkceMethod=S256" \
    -s "config.validateSignature=true" >/dev/null
fi

# ---------- IdP Mappers ----------
ensure_idp_mapper() {
  MAPPER_NAME="$1"
  CLAIM="$2"
  USER_ATTR="$3"

  MID="$(${KC_BIN} get "identity-provider/instances/${IDP_ALIAS}/mappers" -r "${REALM}" --format csv \
    | tr -d '\r"' \
    | grep -F ",${MAPPER_NAME}," \
    | head -n 1 \
    | cut -d, -f1 || true)"

  if [ -n "${MID}" ]; then
    echo "==> IdP mapper ${MAPPER_NAME} exists, updating (id=${MID})"
    ${KC_BIN} update "identity-provider/instances/${IDP_ALIAS}/mappers/${MID}" -r "${REALM}" \
      -s "name=${MAPPER_NAME}" \
      -s "identityProviderAlias=${IDP_ALIAS}" \
      -s "identityProviderMapper=oidc-user-attribute-idp-mapper" \
      -s "config.claim=${CLAIM}" \
      -s "config.\"user.attribute\"=${USER_ATTR}" \
      -s "config.syncMode=INHERIT" >/dev/null
  else
    echo "==> Creating IdP mapper ${MAPPER_NAME}"

    # Try mapper type A then fallback B (both with correct dotted key quoting)
    if ${KC_BIN} create "identity-provider/instances/${IDP_ALIAS}/mappers" -r "${REALM}" -i \
        -s "name=${MAPPER_NAME}" \
        -s "identityProviderAlias=${IDP_ALIAS}" \
        -s "identityProviderMapper=oidc-user-attribute-idp-mapper" \
        -s "config.claim=${CLAIM}" \
        -s "config.\"user.attribute\"=${USER_ATTR}" \
        -s "config.syncMode=INHERIT" >/dev/null 2>&1
    then
      echo "==> Created mapper ${MAPPER_NAME} (oidc-user-attribute-idp-mapper)"
      return 0
    fi

    echo "==> First mapper type failed, trying fallback oidc-user-attribute-mapper..."
    ${KC_BIN} create "identity-provider/instances/${IDP_ALIAS}/mappers" -r "${REALM}" -i \
        -s "name=${MAPPER_NAME}" \
        -s "identityProviderAlias=${IDP_ALIAS}" \
        -s "identityProviderMapper=oidc-user-attribute-mapper" \
        -s "config.claim=${CLAIM}" \
        -s "config.\"user.attribute\"=${USER_ATTR}" \
        -s "config.syncMode=INHERIT"
  fi
}




ensure_idp_mapper "bridge-sub-to-ext-user-id" "sub" "ext_user_id"
ensure_idp_mapper "bridge-email-to-email" "email" "email"
ensure_idp_mapper "bridge-name-to-name" "name" "name"

# ---------- Protocol Mapper: user attribute -> token claim ----------
ensure_user_attr_protocol_mapper() {
  CLIENT_UUID="$1"
  MAPPER_NAME="$2"
  USER_ATTR="$3"
  CLAIM_NAME="$4"

  MID="$(${KC_BIN} get "clients/${CLIENT_UUID}/protocol-mappers/models" -r "${REALM}" --format csv \
    | tr -d '\r"' \
    | grep -F ",${MAPPER_NAME}," \
    | head -n 1 \
    | cut -d, -f1 || true)"

  if [ -n "${MID}" ]; then
    echo "==> Protocol mapper ${MAPPER_NAME} exists, updating (id=${MID})"
    ${KC_BIN} update "clients/${CLIENT_UUID}/protocol-mappers/models/${MID}" -r "${REALM}" \
      -s "name=${MAPPER_NAME}" \
      -s "protocol=openid-connect" \
      -s "protocolMapper=oidc-usermodel-attribute-mapper" \
      -s "config.\"user.attribute\"=${USER_ATTR}" \
      -s "config.\"claim.name\"=${CLAIM_NAME}" \
      -s "config.\"jsonType.label\"=String" \
      -s "config.\"id.token.claim\"=true" \
      -s "config.\"access.token.claim\"=true" \
      -s "config.\"userinfo.token.claim\"=true" >/dev/null
  else
    echo "==> Creating protocol mapper ${MAPPER_NAME}"
    ${KC_BIN} create "clients/${CLIENT_UUID}/protocol-mappers/models" -r "${REALM}" -i \
      -s "name=${MAPPER_NAME}" \
      -s "protocol=openid-connect" \
      -s "protocolMapper=oidc-usermodel-attribute-mapper" \
      -s "config.\"user.attribute\"=${USER_ATTR}" \
      -s "config.\"claim.name\"=${CLAIM_NAME}" \
      -s "config.\"jsonType.label\"=String" \
      -s "config.\"id.token.claim\"=true" \
      -s "config.\"access.token.claim\"=true" \
      -s "config.\"userinfo.token.claim\"=true" >/dev/null
  fi
}


ensure_user_attr_protocol_mapper "${RP_UUID}" "ext-user-id-as-user-id" "ext_user_id" "user_id"

echo "==> Setup finished"
echo "Realm: ${REALM}"
echo "IdP : ${IDP_ALIAS} -> ${BRIDGE_ISSUER}"
echo "Client: ${RP_CLIENT_ID} (redirect ${RP_REDIRECT_URI})"
echo ""
echo "TIP: To skip Keycloak login UI, add kc_idp_hint=${IDP_ALIAS} to the auth request."
