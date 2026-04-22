# syntax=docker/dockerfile:1.7
#
# node:22-alpine pinned by digest. Bump the digest (and rebuild) whenever
# Alpine or Node release a security update — `docker pull node:22-alpine`
# then copy the new sha256 from the pull output.
ARG NODE_IMAGE=node:22-alpine@sha256:8ea2348b068a9544dae7317b4f3aafcdc032df1647bb7d768a05a5cad1a7683f

# ─── Stage 1: dependencies ───
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# Build toolchain is only needed to compile native modules (bcrypt). It's
# confined to this stage and never ends up in the runtime image.
RUN apk add --no-cache --virtual .build-deps python3 make g++ \
    && npm ci --omit=dev --no-audit --no-fund \
    && apk del .build-deps

# ─── Stage 2: runtime ───
FROM ${NODE_IMAGE} AS runtime

# Commit SHA baked in at build time so the running container can report which
# revision it's on (surfaced via /api/version and shown in the UI footer).
ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}

# Runtime-only tools: dig/whois for record queries, ping for ICMP health checks.
# Strip the bundled npm/corepack from the node image — they drag in transitive
# packages (picomatch, fdir, tinyglobby, …) that Scout flags as CVEs even
# though the running app never touches them. The app doesn't invoke npm at
# runtime; deps are already baked in from the deps stage.
RUN apk add --no-cache bind-tools whois iputils tini \
    && rm -rf /usr/local/lib/node_modules/npm \
             /usr/local/lib/node_modules/corepack \
             /usr/local/bin/npm \
             /usr/local/bin/npx \
             /usr/local/bin/corepack \
             /opt/yarn-* \
             /usr/local/bin/yarn \
             /usr/local/bin/yarnpkg \
             /root/.npm /home/node/.npm 2>/dev/null || true

WORKDIR /app

# Copy dependency tree and source. `node` user owns everything so a
# read-only root filesystem still lets the app read its own code.
COPY --chown=node:node --from=deps /app/node_modules ./node_modules
COPY --chown=node:node . .
RUN sed -i 's/\r$//' /app/docker/entrypoint.sh && chmod +x /app/docker/entrypoint.sh

USER node

EXPOSE 8080

# Same probe as docker-compose, duplicated here so `docker run` and
# orchestrators without compose still get health information.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://localhost:8080/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# OCI labels surface provenance in registry UIs and feed Docker Scout.
LABEL org.opencontainers.image.title="DNS Scanner" \
      org.opencontainers.image.description="PWA that monitors DNS records and detects dead endpoints" \
      org.opencontainers.image.source="https://github.com/djlactose/dnsscaner" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/node:22-alpine"

# tini reaps zombies from execFile'd dig/whois/ping children.
ENTRYPOINT ["/sbin/tini", "--", "/bin/sh", "/app/docker/entrypoint.sh"]
CMD ["node", "server.js"]
