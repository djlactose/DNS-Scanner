#!/bin/bash
set -e

cd "$(dirname "$0")"

if [ ! -f .env ]; then
    echo "No .env file found. Generating one with random secrets..."

    if command -v openssl &> /dev/null; then
        gen_secret() { openssl rand -hex 32; }
    else
        gen_secret() { tr -dc 'a-f0-9' < /dev/urandom | head -c 64; }
    fi

    DB_PASSWORD=$(gen_secret)
    REDIS_PASSWORD=$(gen_secret)
    SESSION_SECRET=$(gen_secret)
    ENCRYPTION_KEY=$(gen_secret)

    cp .env.example .env

    sed -i "s/DB_PASSWORD=change_me_to_a_strong_password/DB_PASSWORD=$DB_PASSWORD/" .env
    sed -i "s/REDIS_PASSWORD=change_me_to_a_strong_password/REDIS_PASSWORD=$REDIS_PASSWORD/" .env
    sed -i "s/SESSION_SECRET=change_me_to_a_random_string_at_least_32_chars/SESSION_SECRET=$SESSION_SECRET/" .env
    sed -i "s/ENCRYPTION_KEY=change_me_to_a_random_string_at_least_32_chars/ENCRYPTION_KEY=$ENCRYPTION_KEY/" .env

    chmod 600 .env
    echo ".env file created with random secrets."
else
    echo "Using existing .env file."
fi

docker-compose up -d --build
