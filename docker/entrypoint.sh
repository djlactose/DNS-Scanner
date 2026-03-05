#!/bin/sh
set -e

SECRETS_ENV="/secrets/.env"

# Source secrets from file if it exists (written by init container)
if [ -f "$SECRETS_ENV" ]; then
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
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 64
}

[ -z "$(printenv DB_PASSWORD 2>/dev/null || true)" ] && export DB_PASSWORD=$(gen_secret)
[ -z "$(printenv REDIS_PASSWORD 2>/dev/null || true)" ] && export REDIS_PASSWORD=$(gen_secret)
[ -z "$(printenv SESSION_SECRET 2>/dev/null || true)" ] && export SESSION_SECRET=$(gen_secret)
[ -z "$(printenv ENCRYPTION_KEY 2>/dev/null || true)" ] && export ENCRYPTION_KEY=$(gen_secret)

exec "$@"
