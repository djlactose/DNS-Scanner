#!/bin/sh
set -e

SECRETS_ENV="/secrets/.env"

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

exec "$@"
