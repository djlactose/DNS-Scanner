#!/bin/sh
set -e

echo "[entrypoint] Starting..."

SECRETS_ENV="/secrets/.env"

# Source secrets from file if it exists (written by init container)
if [ -f "$SECRETS_ENV" ]; then
    echo "[entrypoint] Loading secrets from $SECRETS_ENV"
    while IFS='=' read -r key value; do
        [ -z "$key" ] && continue
        case "$key" in \#*) continue ;; esac
        current=$(printenv "$key" 2>/dev/null || true)
        if [ -z "$current" ]; then
            export "$key=$value"
        fi
    done < "$SECRETS_ENV"
fi

# Generate any missing secrets (standalone mode without init container)
gen_secret() {
    node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
}

if [ -z "$(printenv DB_PASSWORD 2>/dev/null || true)" ]; then
    echo "[entrypoint] Generating DB_PASSWORD"
    export DB_PASSWORD=$(gen_secret)
fi
if [ -z "$(printenv REDIS_PASSWORD 2>/dev/null || true)" ]; then
    echo "[entrypoint] Generating REDIS_PASSWORD"
    export REDIS_PASSWORD=$(gen_secret)
fi
if [ -z "$(printenv SESSION_SECRET 2>/dev/null || true)" ]; then
    echo "[entrypoint] Generating SESSION_SECRET"
    export SESSION_SECRET=$(gen_secret)
fi
if [ -z "$(printenv ENCRYPTION_KEY 2>/dev/null || true)" ]; then
    echo "[entrypoint] Generating ENCRYPTION_KEY"
    export ENCRYPTION_KEY=$(gen_secret)
fi

echo "[entrypoint] Secrets ready, starting app..."
exec "$@"
