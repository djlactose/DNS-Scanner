FROM node:22-alpine

RUN apk add --no-cache bind-tools whois iputils

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

COPY . .
RUN chmod +x /app/docker/entrypoint.sh

USER node

EXPOSE 8080

ENTRYPOINT ["/bin/sh", "/app/docker/entrypoint.sh"]
CMD ["node", "server.js"]
