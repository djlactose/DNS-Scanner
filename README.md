# DNS Scanner

A containerized Progressive Web App (PWA) that monitors DNS records across multiple domains, detects dead endpoints, identifies subdomain takeover risks, and sends notifications when issues are found.

## Features

### DNS Enumeration

- **DNS Provider Integrations** - Fetch complete zone records from Cloudflare, AWS Route 53, DigitalOcean, and GoDaddy APIs
- **AXFR Zone Transfers** - Attempts zone transfers against each nameserver
- **Per-Type Queries** - Queries all record types (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, SOA)
- **Certificate Transparency Logs** - Discovers subdomains via crt.sh certificate search
- **NSEC Walking** - Enumerates DNSSEC-signed zones via NSEC chain walking (up to 500 steps)
- **Subdomain Brute-forcing** - Tests 150+ common subdomains including web, mail, dev, DevOps, Microsoft 365, DKIM selectors, and cloud verification records

### Monitoring & Detection

- **Health Checking** - HTTPS, HTTP, TCP port scanning (42 common ports), ICMP ping
- **Full Port Scanning** - Scans 42 ports on first discovery (FTP, SSH, Telnet, SMTP, DNS, HTTP/S, POP3, IMAP, LDAP, SMB, RDP, MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, Kubernetes API, VNC, WinRM, cPanel, Prometheus, and more), then quick-checks only known open ports on subsequent scans
- **Manual Port Rescan** - Trigger a full port rescan on any individual record on demand
- **Dead Record Detection** - Records marked dead after 3 consecutive failed checks across scans
- **Subdomain Takeover Detection** - Dangling CNAME detection for AWS S3, GitHub Pages, Heroku, Azure, Netlify, CloudFront, Fastly, Shopify, and 20+ cloud services
- **Cloudflare Tunnel Health** - Auto-detects CNAMEs pointing to `*.cfargotunnel.com` and reports tunnel status (healthy/degraded/down) from the Cloudflare API
- **DNS Propagation Monitoring** - Compare results across Google, Cloudflare, Quad9, and OpenDNS resolvers
- **Domain Expiry Monitoring** - WHOIS-based expiry tracking with 90/30/14/7 day warnings
- **DNS Change Detection** - Track when record values change between scans
- **SSL Certificate Tracking** - Monitor validity, issuer, expiration, and errors
- **IPv6 Connectivity Detection** - Auto-detects IPv6 support, skips AAAA checks when unavailable

### Notifications

- **Push Notifications** - Browser push via Web Push API (VAPID keys auto-generated)
- **Email Notifications** - Configurable SMTP with AES-256-GCM encrypted credentials
- **Webhooks** - HMAC-SHA256 signed webhooks with retry logic and delivery history
  - Event types: record dead/recovered, takeover risk, DNS change, domain expiry, scan completed, propagation inconsistency
  - Integrations: Slack, Discord, Teams, generic HTTP
- **Tag-Based Filtering** - Receive notifications only for domains matching specific tags
- **Test Notifications** - Send test push/email/webhook to verify configuration

### Authentication & User Management

- **Username/Password** - Bcrypt hashing (cost factor 12), account lockout after 5 failed attempts
- **Passkeys (WebAuthn)** - Passwordless login, two-factor authentication, or either mode
- **Google OAuth 2.0** - Optional SSO with configurable client credentials
- **User Invitations** - Email-based invites with 7-day expiring tokens and role assignment
- **Password Reset** - Email-based password recovery
- **Multi-User Roles** - Admin (full access) and Viewer (read-only + scan) roles
- **Tag-Based Access Control** - Restrict viewers to specific tagged domains
- **User Import/Export** - Bulk user management via CSV
- **API Key Management** - Generate API keys for programmatic access

### Organization & Bulk Operations

- **Tagging & Grouping** - Color-coded tags for filtering and targeted notifications
- **Bulk Import** - CSV import up to 100 domains at once (with preview)
- **Bulk Actions** - Select multiple domains for scanning, deleting, or tagging
- **Export & Reporting** - CSV export and HTML print-ready reports

### UI & Experience

- **PWA** - Installable, offline-capable, responsive design with auto light/dark theme
- **Real-time Updates** - Server-Sent Events for live scan progress with record counters
- **Trend Charts** - Canvas-based health trend visualization
- **Dashboard** - Summary cards, dead record carousel, recent changes timeline, worker health status
- **Record Filtering** - Filter by status (alive, dead, new, changed), type, or name
- **Skeleton Loaders** - Loading states while fetching data
- **Mobile Navigation** - Bottom navigation bar on mobile devices
- **Record Dismissal** - Dismiss dead record alerts from the dashboard

### Administration

- **System Settings UI** - Configure general, authentication, scanner performance, and integration settings from the browser
- **Scanner Performance Tuning** - Configurable health check timeout, scan timeout, max concurrent checks, failure threshold
- **Audit Logging** - All admin actions logged with user attribution and timestamps
- **Worker Health Monitoring** - Background worker heartbeat and status display
- **Background Scanning** - Configurable intervals per domain (15 min to 7 days)
- **Data Cleanup** - Auto-deletes health checks older than 90 days and webhook deliveries older than 30 days

## Architecture

| Service | Technology | Purpose |
|---------|-----------|---------|
| **app** | Node.js 22 + Express | API server, web UI, background worker |
| **db** | PostgreSQL 16 | Primary data store |

## Quick Start

### 1. Start the application

```bash
./start.sh
```

This generates a `.env` file with random secrets and starts the containers. If you prefer to manage secrets manually, copy `.env.example` to `.env`, fill in your own values, and run `docker compose up -d`.

### 2. Access the app

Open `http://localhost:8080` in your browser.

**Bootstrap the first admin:** registration is disabled by default. To create the first user, temporarily set `REGISTRATION_ENABLED=true` in `.env` (or the compose environment), restart the app, register — the first user is automatically an admin — then set `REGISTRATION_ENABLED=false` and restart again. After that, additional users are added via the invite flow in Settings → Users.

## Configuration

All configuration is via environment variables (see `.env.example`). Secrets (`DB_PASSWORD`, `SESSION_SECRET`, `ENCRYPTION_KEY`) are auto-generated on first run if not provided:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_PASSWORD` | No | *auto-generated* | PostgreSQL password |
| `SESSION_SECRET` | No | *auto-generated* | Session encryption key (min 32 chars) |
| `ENCRYPTION_KEY` | No | *auto-generated* | SMTP credential encryption key (min 32 chars) |
| `REGISTRATION_ENABLED` | No | `false` | Allow new user registration. Enable only to bootstrap the first admin, then disable again. |
| `ALLOW_PRIVATE_RANGES` | No | `false` | Allow scanning private IP ranges |
| `MAX_DOMAINS` | No | `50` | Maximum domains per instance |
| `APP_PORT` | No | `8080` | Host port for web UI |

Additional settings (DNS provider API keys, OAuth credentials, scanner performance) can be configured through the System Settings UI after deployment.

## Security

- All database queries use parameterized queries (no SQL injection)
- Frontend uses `textContent` only (no XSS via innerHTML)
- Content Security Policy enforced
- SSRF protection blocks private IP ranges by default
- Passwords hashed with bcrypt (cost factor 12)
- Account lockout after 5 failed attempts (15 min)
- SMTP credentials and API keys encrypted with AES-256-GCM at rest
- Webhooks signed with HMAC-SHA256
- All containers run as non-root with minimal capabilities
- Internal services not exposed to host network
- Rate limiting on login, registration, scan triggers, password reset, and general API
- Gzip compression enabled
- Audit logging for all admin actions
- CSRF token protection
- Security headers (X-Content-Type-Options, X-Frame-Options, Permissions-Policy)

## Ports

| Service | Container Port | Host Port            | Description              |
|---------|----------------|----------------------|--------------------------|
| **app** | 8080           | `${APP_PORT:-8080}`  | Web UI and API           |
| **db**  | 5432           | *not exposed*        | PostgreSQL (internal only) |

Only the app is exposed to the host network. The database communicates over an internal Docker bridge network.

## Volumes

| Volume    | Container       | Mount Path                 | Purpose                                                                  |
|-----------|-----------------|----------------------------|--------------------------------------------------------------------------|
| `pgdata`  | db (PostgreSQL) | `/var/lib/postgresql/data` | Database storage — all domains, records, scan history, and user accounts |
| `secrets` | db, app         | `/secrets`                 | Auto-generated secrets (Portainer deploy only)                           |

These volumes persist across container restarts and rebuilds. To manage them:

```bash
# Back up the database
docker compose exec db pg_dump -U dnsscanner dnsscanner > backup.sql

# Restore from backup
docker compose exec -T db psql -U dnsscanner dnsscanner < backup.sql

# Reset all data (destructive — removes everything)
docker compose down -v
```

## How "Dead" Is Determined

A record is **dead** only when **nothing responds at all** — no HTTP, no TCP port, no ICMP ping. A server returning HTTP 500 or having an expired SSL certificate is still considered **alive** (the server is responding, just unhealthy).

Records are marked dead after **3 consecutive failed health checks** across scans to avoid false positives from transient issues.

### Check Cascade by Record Type

| Type | Checks (stops at first success) |
|------|-------------------------------|
| A/AAAA | Full port scan (42 ports, first discovery) or known-port quick check -> HTTPS/HTTP -> ICMP |
| CNAME | Resolve target, then same as A/AAAA |
| MX | TCP 25 -> TCP 587 -> TCP 465 -> ICMP |
| NS | DNS query -> ICMP |
| SRV | TCP host:port -> ICMP |
| TXT/CAA/SOA | Skipped (informational) |

## DNS Provider Integrations

Configure API credentials in System Settings to fetch complete zone records directly from your DNS provider:

| Provider | Required Credentials | Permissions |
|----------|---------------------|-------------|
| **Cloudflare** | API Token | Zone:Read, DNS:Read |
| **AWS Route 53** | Access Key + Secret Key | Route53 read access |
| **DigitalOcean** | Personal Access Token | Domain read access |
| **GoDaddy** | API Key + API Secret | Domain read access |

When configured, provider APIs are queried first during scans, providing complete and authoritative zone data before falling back to DNS enumeration techniques.

### Cloudflare Tunnel Monitoring

The scanner automatically detects CNAME records pointing to `{uuid}.cfargotunnel.com` and reports tunnel health from the Cloudflare API. This is **separate** from the DNS zone integration above and requires an account-scoped permission.

| Setting | Value |
| --- | --- |
| `cloudflare_api_token` | API token with **Account · Cloudflare Tunnel · Read** |
| `cloudflare_account_id` | 32-char account ID that owns the tunnels (shown in the Cloudflare dashboard sidebar of any zone's overview page) |
| `cloudflare_tunnel_check_enabled` | `true` (default) |

Create the token at <https://dash.cloudflare.com/profile/api-tokens> → Create Token → Custom token, then add the permission:

- **Account** · **Cloudflare Tunnel** · **Read**
- Account Resources: *Include → Specific account →* the account that owns the tunnels.

You can reuse the same token for zone reads by adding **Zone · Zone · Read** and **Zone · DNS · Read** to it. If tunnel records show SKIPPED with "Cloudflare Tunnel API unavailable" or the scanner logs `[TUNNEL] API error: Authentication error`, the token is missing the Tunnel:Read scope or the account ID doesn't match the token's account.

## API

All endpoints require authentication unless noted. Admin-only endpoints require `role: admin`.

### Auth

- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Current user
- `PUT /api/auth/password` - Change password
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Complete password reset
- `POST /api/auth/passkey/register-options` - WebAuthn registration
- `POST /api/auth/passkey/register-verify` - Verify WebAuthn registration
- `POST /api/auth/passkey/login-options` - WebAuthn login
- `POST /api/auth/passkey/login-verify` - Verify WebAuthn login
- `POST /api/auth/passkey/2fa-options` - Two-factor challenge
- `POST /api/auth/passkey/verify-2fa` - Verify two-factor
- `POST /api/auth/accept-invite` - Accept invitation

### Domains (admin: create/update/delete)

- `GET /api/domains` - List domains
- `POST /api/domains` - Add domain
- `PUT /api/domains/:id` - Update domain
- `DELETE /api/domains/:id` - Delete domain
- `POST /api/domains/import` - Bulk CSV import
- `POST /api/domains/:id/tags/:tagId` - Add tag to domain
- `DELETE /api/domains/:id/tags/:tagId` - Remove tag from domain
- `POST /api/domains/bulk/scan` - Bulk scan
- `POST /api/domains/bulk/delete` - Bulk delete
- `POST /api/domains/bulk/tag` - Bulk tag

### Scanning

- `POST /api/domains/:id/scan` - Manual scan
- `POST /api/scan-all` - Scan all domains
- `GET /api/domains/:id/scans` - Scan history
- `GET /api/scans/:id` - Scan details

### Records

- `GET /api/domains/:id/records` - DNS records with health status (filterable by status)
- `GET /api/records/:id/history` - Health check history
- `GET /api/records/:id/changes` - Record change history
- `GET /api/domains/:id/changes` - Domain-wide change history
- `PUT /api/records/:id/dismiss` - Dismiss dead record alert
- `POST /api/records/:id/port-scan` - Trigger full port rescan

### Dashboard

- `GET /api/dashboard` - Summary stats, dead records, recent changes, IPv6 status

### Export & Data

- `GET /api/domains/:id/export/csv` - CSV download
- `GET /api/domains/:id/export/report` - HTML report
- `GET /api/domains/:id/propagation` - DNS propagation data
- `GET /api/domains/:id/whois` - WHOIS data

### Notifications & Webhooks

- `GET/PUT /api/notifications/settings` - Notification preferences
- `POST /api/notifications/test-push` - Test push notification
- `POST /api/notifications/test-email` - Test email
- `GET /api/push/vapid-key` - VAPID public key
- `POST /api/push/subscribe` - Register push subscription
- `DELETE /api/push/subscribe` - Unsubscribe
- `GET/PUT /api/smtp` - SMTP configuration
- `GET/POST/PUT/DELETE /api/webhooks` - Webhook CRUD
- `POST /api/webhooks/:id/test` - Test webhook
- `GET /api/webhooks/:id/deliveries` - Delivery history

### Users (admin)

- `GET /api/users` - List users
- `PUT /api/users/:id` - Update user role/access
- `DELETE /api/users/:id` - Delete user
- `POST /api/users/invite` - Invite user
- `GET /api/users/invites` - List invitations
- `DELETE /api/users/invites/:id` - Revoke invitation
- `GET /api/users/export` - Export users CSV
- `POST /api/users/import` - Import users CSV

### Tags (admin)

- `GET/POST /api/tags` - List/create tags
- `PUT/DELETE /api/tags/:id` - Update/delete tags

### Settings (admin)

- `GET/PUT /api/settings/system` - System settings
- `GET /api/settings/audit-log` - Audit log
- `GET /api/settings/worker/status` - Worker health

### Real-time

- `GET /api/events` - Server-Sent Events stream

### Health

- `GET /health` - Health check (DB connectivity, uptime)

## Development

```bash
# Run without Docker (requires PostgreSQL)
npm install
DB_PASSWORD=dev SESSION_SECRET=$(openssl rand -hex 32) ENCRYPTION_KEY=$(openssl rand -hex 32) node server.js
```

## Links

- [Source Code](https://github.com/djlactose/DNS-Scanner)
- [Buy Me a Coffee](https://buymeacoffee.com/djlactose)

## License

MIT
