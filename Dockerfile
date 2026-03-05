FROM node:22-alpine

RUN apk add --no-cache bind-tools whois iputils

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

COPY . .

USER node

EXPOSE 8080

CMD ["node", "server.js"]
