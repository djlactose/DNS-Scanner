#!/bin/sh
set -e

SECRETS_DIR="/secrets"
SECRETS_ENV="$SECRETS_DIR/.env"

if [ -f "$SECRETS_ENV" ]; then
    echo "[init] Existing secrets found, skipping generation."
    exit 0
fi

echo "[init] Generating secrets..."

gen_secret() {
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 64
}

# Use env vars if provided, otherwise generate random secrets
DB_PASSWORD="${DB_PASSWORD:-$(gen_secret)}"
SESSION_SECRET="${SESSION_SECRET:-$(gen_secret)}"
ENCRYPTION_KEY="${ENCRYPTION_KEY:-$(gen_secret)}"

cat > "$SECRETS_ENV" <<EOF
DB_PASSWORD=$DB_PASSWORD
SESSION_SECRET=$SESSION_SECRET
ENCRYPTION_KEY=$ENCRYPTION_KEY
EOF

chmod 644 "$SECRETS_ENV"

echo "[init] Secrets ready."
