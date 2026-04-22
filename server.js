'use strict';

const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const { getPool, query, initSchema } = require('./db');
const { startWorker } = require('./worker');
const { csrfProtect } = require('./middleware');
const { sseClients, setupSSE } = require('./sse');
const { initSettings } = require('./settings-service');

const app = express();
const PORT = parseInt(process.env.PORT || '8080', 10);

// ─── Startup validation ───
function validateEnv() {
  const required = ['DB_PASSWORD', 'SESSION_SECRET', 'ENCRYPTION_KEY'];
  for (const key of required) {
    if (!process.env[key]) { console.error(`[FATAL] Missing required env var: ${key}`); process.exit(1); }
  }
  if (process.env.SESSION_SECRET.length < 32) { console.error('[FATAL] SESSION_SECRET must be at least 32 characters'); process.exit(1); }
  if (process.env.ENCRYPTION_KEY.length < 32) { console.error('[FATAL] ENCRYPTION_KEY must be at least 32 characters'); process.exit(1); }
}

// ─── Security headers ───
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(compression());
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // 'unsafe-inline' on script-src is required by the many inline onclick
  // handlers in public/app.js; removing it means refactoring every button.
  // All other directives are tightened: no plugins, no framing, no base-tag
  // injection, forms locked to same origin.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '));
  // HSTS only when the request actually arrived over HTTPS (directly or via
  // a trusted proxy). Sending it over plain HTTP is ignored by browsers but
  // flags in scanners.
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '1mb' }));

// ─── Rate limiters ───
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.ip });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, keyGenerator: (req) => req.ip });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const scanLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, keyGenerator: (req) => req.session?.userId?.toString() || req.ip });
const resetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.ip });

// Session middleware reference (set up in start())
let sessionMiddleware;
app.use((req, res, next) => {
  if (sessionMiddleware) return sessionMiddleware(req, res, next);
  next();
});

// CSRF protection
app.use(csrfProtect);

// Rate limiting
app.use('/api/', apiLimiter);

// Service worker must never be cached
app.get('/service-worker.js', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'service-worker.js'));
});
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

function setupSession() {
  sessionMiddleware = session({
    store: new PgSession({ pool: getPool(), tableName: 'session', createTableIfMissing: false }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production' && process.env.BEHIND_HTTPS === 'true',
      sameSite: 'lax',
    },
  });
}

// ─── Health endpoint (with DB check) ───
app.get('/health', async (req, res) => {
  const start = Date.now();
  let dbStatus = 'ok';
  try {
    await query('SELECT 1');
  } catch (err) {
    dbStatus = 'error';
  }
  res.status(dbStatus === 'ok' ? 200 : 503).json({
    status: dbStatus === 'ok' ? 'ok' : 'degraded',
    uptime: Math.floor(process.uptime()),
    db: dbStatus,
    responseMs: Date.now() - start,
  });
});

// ─── Mount route modules ───
// Apply rate limiters to specific route groups
const authRoutes = require('./routes/auth');
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/passkey/login-options', loginLimiter);
app.use('/api/auth/passkey/login-verify', loginLimiter);
app.use('/api/auth/passkey/2fa-options', loginLimiter);
app.use('/api/auth/passkey/verify-2fa', loginLimiter);
app.use('/api/auth/register', registerLimiter);
app.use('/api/auth/accept-invite', registerLimiter);
app.use('/api/auth/forgot-password', resetLimiter);
app.use('/api/auth/reset-password', resetLimiter);
app.use('/api/auth', authRoutes);

const userRoutes = require('./routes/users');
app.use('/api/users', userRoutes);

const domainRoutes = require('./routes/domains');
app.use('/api/domains/:id/scan', scanLimiter);
app.use('/api/scan-all', scanLimiter);
app.use('/api', domainRoutes);

const dashboardRoutes = require('./routes/dashboard');
app.use('/api', dashboardRoutes);

const tagRoutes = require('./routes/tags');
app.use('/api/tags', tagRoutes);

const notificationRoutes = require('./routes/notifications');
app.use('/api', notificationRoutes);

const webhookRoutes = require('./routes/webhooks');
app.use('/api/webhooks', webhookRoutes);

const settingsRoutes = require('./routes/settings');
app.use('/api/settings', settingsRoutes);

// ─── SSE ───
setupSSE(app);

// ─── SPA fallback ───
app.get('/{*splat}', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Error handler ───
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Bootstrap ───
let server;

async function start() {
  validateEnv();

  // Retry DB connection (Swarm ignores depends_on, so DB may not be ready yet)
  const MAX_RETRIES = 20;
  for (let attempt = 1; ; attempt++) {
    try {
      await initSchema();
      await initSettings();
      break;
    } catch (err) {
      if (attempt >= MAX_RETRIES) throw err;
      const delay = Math.min(attempt * 1000, 5000);
      console.log(`[DB] Connection attempt ${attempt}/${MAX_RETRIES} failed (${err.code || err.message}), retrying in ${delay / 1000}s...`);
      await new Promise(r => setTimeout(r, delay));
    }
  }

  setupSession();

  // Clean up expired WebAuthn challenges every 10 minutes
  setInterval(() => {
    query('DELETE FROM webauthn_challenges WHERE expires_at < NOW()').catch(() => {});
  }, 10 * 60 * 1000);

  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SERVER] DNS Scanner running on port ${PORT}`);
    startWorker();
  });
}

// ─── Graceful shutdown ───
function gracefulShutdown(signal) {
  console.log(`[SERVER] ${signal} received, shutting down gracefully...`);
  if (server) {
    server.close(() => {
      console.log('[SERVER] HTTP server closed');
    });
  }
  // Close SSE clients
  for (const [id, client] of sseClients) {
    try { client.end(); } catch (e) {}
    sseClients.delete(id);
  }
  // Close DB pool
  const pool = getPool();
  pool.end().then(() => {
    console.log('[SERVER] DB pool closed');
    process.exit(0);
  }).catch(() => process.exit(1));
  // Force exit after 10s
  setTimeout(() => { process.exit(1); }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

start().catch(err => {
  console.error('[FATAL]', err.message || err);
  if (err.stack) console.error(err.stack);
  process.exit(1);
});

module.exports = { app, broadcastSSE: require('./sse').broadcastSSE };
