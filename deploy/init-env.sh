#!/usr/bin/env bash
# Writes .env for docker-compose.prod.yml with random secrets.
# Usage: DOMAIN=203.0.113.10.sslip.io ./deploy/init-env.sh
# Optional: LAB_USER (default analyst), LAB_PASSWORD (default random).
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -e .env ]]; then
  echo ".env already exists. Delete it first if you really want new secrets." >&2
  exit 1
fi

domain="${DOMAIN:-}"
if [[ -z "$domain" ]]; then
  read -r -p "Domain (for example 203.0.113.10.sslip.io): " domain
fi
if [[ -z "$domain" ]]; then
  echo "A domain is required." >&2
  exit 1
fi

secret() { openssl rand -hex 32; }

lab_user="${LAB_USER:-analyst}"
lab_password="${LAB_PASSWORD:-$(openssl rand -hex 12)}"
lab_password_hash="$(docker run --rm caddy:2 caddy hash-password --plaintext "$lab_password")"

umask 077
cat > .env <<EOF
DOMAIN=$domain
SECRET_KEY=$(secret)
POSTGRES_PASSWORD=$(secret)
REDIS_PASSWORD=$(secret)
API_KEYS=$(secret)
LAB_API_KEY=$(secret)
LAB_USER=$lab_user
LAB_PASSWORD_HASH='$lab_password_hash'
RATE_LIMIT_PER_MINUTE=600
EOF

echo "Created .env (readable only by you). Keep it secret and back it up."
echo "API docs:      https://$domain/docs"
echo "Red-Team Lab:  https://lab.$domain  (user: $lab_user, password: $lab_password)"
echo "Sensor key:    the API_KEYS value in .env, sent as the X-API-Key header"
