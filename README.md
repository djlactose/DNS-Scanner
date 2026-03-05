# DNS Scanner

A containerized Progressive Web App (PWA) that monitors DNS records across multiple domains, detects dead endpoints, identifies subdomain takeover risks, and sends notifications when issues are found.

## Features

- **Full DNS Enumeration** - AXFR zone transfer + per-type queries (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, SOA)
- **Health Checking** - HTTPS, HTTP, TCP ports (443, 80, 22, 8443, 8080, 3389, 21), ICMP ping
- **Dead Record Detection** - Records marked dead after 3 consecutive failed checks across scans
- **Subdomain Takeover Detection** - Dangling CNAME detection for AWS S3, GitHub Pages, Heroku, Azure, Netlify, and 20+ cloud services
- **DNS Propagation Monitoring** - Compare results across Google, Cloudflare, Quad9, and OpenDNS resolvers
- **Domain Expiry Monitoring** - Whois-based expiry tracking with 90/30/14/7 day warnings
- **DNS Change Detection** - Track when record values change between scans
- **SSL Certificate Tracking** - Monitor validity, expiration, and errors
- **Push Notifications** - Browser push via Web Push API (VAPID)
- **Email Notifications** - Configurable SMTP with encrypted credentials
- **Webhooks** - HMAC-signed webhooks with retry logic (Slack, Discord, Teams, Generic)
- **Multi-User Auth** - Admin/viewer roles, bcrypt password hashing, session management, account lockout
- **Tagging & Grouping** - Tag domains for filtering and targeted notifications
- **Bulk Import** - CSV import up to 100 domains at once
- **Export & Reporting** - CSV export and HTML print-ready reports
- **Trend Charts** - Canvas-based health trend visualization
- **Real-time Updates** - Server-Sent Events for live scan progress
- **PWA** - Installable, offline-capable, responsive design with auto light/dark theme
- **Background Scanning** - Configurable intervals per domain (15 min to 7 days)

## Architecture

| Service | Technology | Purpose |
|---------|-----------|---------|
| **app** | Node.js 22 + Express | API server, web UI |
| **worker** | Node.js 22 | Background scan scheduler |
| **nginx** | Nginx Alpine | Reverse proxy, security headers, rate limiting |
| **db** | PostgreSQL 16 | Primary data store |
| **redis** | Redis 7 | Distributed locks, scan coordination |

## Quick Start

### 1. Start the application

```bash
./start.sh
```

This will auto-generate a `.env` file with random passwords and secrets on first run, then start all containers. To customize settings, edit `.env` before running (see `.env.example` for all options).

### 2. Access the app

Open `http://localhost:8082` in your browser.

The first user to register automatically becomes an admin.

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_PASSWORD` | No | *auto-generated* | PostgreSQL password |
| `SESSION_SECRET` | No | *auto-generated* | Session encryption key (min 32 chars) |
| `ENCRYPTION_KEY` | No | *auto-generated* | SMTP credential encryption key (min 32 chars) |
| `REDIS_PASSWORD` | No | *auto-generated* | Redis password |
| `REGISTRATION_ENABLED` | No | `true` | Allow new user registration |
| `ALLOW_PRIVATE_RANGES` | No | `false` | Allow scanning private IP ranges |
| `MAX_DOMAINS` | No | `50` | Maximum domains per instance |
| `NGINX_PORT` | No | `8082` | Host port for web UI |

## Security

- All database queries use parameterized queries (no SQL injection)
- Frontend uses `textContent` only (no XSS via innerHTML)
- Content Security Policy enforced
- SSRF protection blocks private IP ranges by default
- Passwords hashed with bcrypt (cost factor 12)
- Account lockout after 5 failed attempts (15 min)
- SMTP credentials encrypted with AES-256-GCM at rest
- Webhooks signed with HMAC-SHA256
- All containers run as non-root with minimal capabilities
- Redis password-protected
- Internal services not exposed to host network
- Rate limiting on login, registration, scan triggers, and general API

## Volumes

| Volume   | Container       | Mount Path                 | Purpose                                                                  |
|----------|-----------------|----------------------------|--------------------------------------------------------------------------|
| `pgdata` | db (PostgreSQL) | `/var/lib/postgresql/data`  | Database storage — all domains, records, scan history, and user accounts |

The `pgdata` volume persists across container restarts and rebuilds. To manage it:

```bash
# Back up the database
docker-compose exec db pg_dump -U dnsscanner dnsscanner > backup.sql

# Restore from backup
docker-compose exec -T db psql -U dnsscanner dnsscanner < backup.sql

# Reset all data (destructive — removes everything)
docker-compose down -v
```

Redis is used only for ephemeral locks and coordination, so it does not require a persistent volume.

## How "Dead" Is Determined

A record is **dead** only when **nothing responds at all** — no HTTP, no TCP port, no ICMP ping. A server returning HTTP 500 or having an expired SSL certificate is still considered **alive** (the server is responding, just unhealthy).

Records are marked dead after **3 consecutive failed health checks** across scans to avoid false positives from transient issues.

### Check Cascade by Record Type

| Type | Checks (stops at first success) |
|------|-------------------------------|
| A/AAAA | HTTPS -> HTTP -> TCP ports (443,80,22,8443,8080,3389,21) -> ICMP |
| CNAME | Resolve target, then same as A/AAAA |
| MX | TCP 25 -> TCP 587 -> TCP 465 -> ICMP |
| NS | DNS query -> ICMP |
| SRV | TCP host:port -> ICMP |
| TXT/CAA/SOA | Skipped (informational) |

## API

All endpoints require authentication unless noted. Admin-only endpoints require `role: admin`.

### Auth
- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Current user

### Domains (admin: create/update/delete)
- `GET /api/domains` - List domains
- `POST /api/domains` - Add domain
- `PUT /api/domains/:id` - Update domain
- `DELETE /api/domains/:id` - Delete domain
- `POST /api/domains/import` - Bulk CSV import

### Scanning
- `POST /api/domains/:id/scan` - Manual scan
- `POST /api/scan-all` - Scan all domains
- `GET /api/domains/:id/scans` - Scan history

### Records
- `GET /api/domains/:id/records` - DNS records with health status
- `GET /api/records/:id/history` - Health check history
- `GET /api/records/:id/changes` - DNS change history

### Dashboard
- `GET /api/dashboard` - Summary stats, dead records, recent changes

### Export
- `GET /api/domains/:id/export/csv` - CSV download
- `GET /api/domains/:id/export/report` - HTML report

### Notifications & Webhooks
- `GET/PUT /api/notifications/settings` - User notification preferences
- `POST /api/push/subscribe` - Register push subscription
- `GET/POST/PUT/DELETE /api/webhooks` - Webhook management

### Real-time
- `GET /api/events` - Server-Sent Events stream

## Development

```bash
# Run without Docker (requires PostgreSQL and Redis)
npm install
DB_PASSWORD=dev SESSION_SECRET=$(openssl rand -hex 32) ENCRYPTION_KEY=$(openssl rand -hex 32) node server.js
```

## License

MIT
