'use strict';

const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcrypt');
const path = require('path');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('node:crypto');
const { getPool, query, initSchema } = require('./db');
const { encrypt, decrypt } = require('./crypto-utils');
const {
  DOMAIN_REGEX, USER_ROLES, SCAN_STATUS, SCAN_TRIGGER,
  WEBHOOK_EVENT_TYPES, HEALTH_STATUS, CONSECUTIVE_FAILURES_THRESHOLD,
} = require('./constants');

const app = express();
const PORT = parseInt(process.env.PORT || '8080', 10);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });

// SSE clients
const sseClients = new Map();

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
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'");
  next();
});

app.use(express.json({ limit: '1mb' }));

// ─── Rate limiters ───
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.ip });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, keyGenerator: (req) => req.ip });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const scanLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, keyGenerator: (req) => req.session?.userId?.toString() || req.ip });

// Session middleware reference (set up in start())
let sessionMiddleware;
// All routes use this lazy session wrapper so they work regardless of registration order
app.use((req, res, next) => {
  if (sessionMiddleware) return sessionMiddleware(req, res, next);
  next();
});
app.use('/api/', apiLimiter);
// Service worker must never be cached
app.get('/service-worker.js', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'service-worker.js'));
});
app.use(express.static(path.join(__dirname, 'public')));

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
      sameSite: 'strict',
    },
  });
}

// ─── Auth middleware ───
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Authentication required' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Authentication required' });
  if (req.session.role !== USER_ROLES.ADMIN) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ─── Input validation helpers ───
function validateId(req, res, next) {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid ID' });
  req.params.id = id;
  next();
}

function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length > 253) return false;
  return DOMAIN_REGEX.test(domain);
}

// ─── Health endpoint ───
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ─── Auth routes ───
app.post('/api/auth/register', registerLimiter, async (req, res) => {
  try {
    if (process.env.REGISTRATION_ENABLED === 'false') return res.status(403).json({ error: 'Registration is disabled' });
    const { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-30 alphanumeric characters or underscores' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });

    const existing = await query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'Username already taken' });

    // Use transaction with advisory lock to prevent race condition on first-user admin registration
    const client = await require('./db').getPool().connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1)'); // serialize first-user check
      const userCount = await client.query('SELECT COUNT(*) as count FROM users');
      const role = parseInt(userCount.rows[0].count) === 0 ? USER_ROLES.ADMIN : USER_ROLES.VIEWER;
      const passwordHash = await bcrypt.hash(password, 12);
      const result = await client.query(
        'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, role',
        [username, email || null, passwordHash, role]
      );
      const user = result.rows[0];
      await client.query('INSERT INTO notification_settings (user_id) VALUES ($1)', [user.id]);
      await client.query('COMMIT');
      req.session.userId = user.id;
      req.session.role = user.role;
      console.log(`[AUTH] User registered: ${username} (${role})`);
      res.status(201).json({ id: user.id, username: user.username, role: user.role });
    } catch (innerErr) {
      await client.query('ROLLBACK');
      throw innerErr;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('[AUTH] Registration error:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const result = await query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({ error: 'Account locked. Try again later.' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      const attempts = (user.failed_login_attempts || 0) + 1;
      const lockUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
      await query('UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3', [attempts, lockUntil, user.id]);
      console.log(`[AUTH] Failed login for ${username} (attempt ${attempts})`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);
    const userData = { id: user.id, username: user.username, role: user.role, email: user.email };
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = user.id;
      req.session.role = user.role;
      console.log(`[AUTH] Login: ${username}`);
      res.json(userData);
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT id, username, email, role, created_at FROM users WHERE id = $1', [req.session.userId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ─── User management (admin) ───
app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const result = await query('SELECT id, username, email, role, created_at FROM users ORDER BY created_at');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch users' }); }
});

app.put('/api/users/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const { role, email } = req.body;
    if (parseInt(req.params.id) === req.session.userId && role && role !== req.session.role) {
      return res.status(400).json({ error: 'Cannot change your own role' });
    }
    if (role && !Object.values(USER_ROLES).includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const updates = [];
    const params = [];
    let i = 1;
    if (role) { updates.push(`role = $${i++}`); params.push(role); }
    if (email !== undefined) { updates.push(`email = $${i++}`); params.push(email || null); }
    if (updates.length === 0) return res.status(400).json({ error: 'Nothing to update' });
    params.push(req.params.id);
    await query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${i}`, params);
    console.log(`[AUTH] User ${req.params.id} updated by admin ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update user' }); }
});

app.delete('/api/users/:id', requireAdmin, validateId, async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
    await query('DELETE FROM users WHERE id = $1', [req.params.id]);
    console.log(`[AUTH] User ${req.params.id} deleted by admin ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete user' }); }
});

app.put('/api/auth/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const result = await query('SELECT password_hash FROM users WHERE id = $1', [req.session.userId]);
    const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(newPassword, 12);
    await query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.session.userId]);
    // Invalidate other sessions
    const currentSid = req.sessionID;
    await query("DELETE FROM session WHERE sid != $1 AND sess::text LIKE $2", [currentSid, `%"userId":${req.session.userId}%`]);
    console.log(`[AUTH] Password changed for user ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to change password' }); }
});

// ─── Tags ───
app.get('/api/tags', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM tags ORDER BY name');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch tags' }); }
});

app.post('/api/tags', requireAdmin, async (req, res) => {
  try {
    const { name, color } = req.body;
    if (!name || name.length > 50) return res.status(400).json({ error: 'Tag name required (max 50 chars)' });
    const result = await query('INSERT INTO tags (name, color, created_by) VALUES ($1, $2, $3) RETURNING *', [name, color || '#3b82f6', req.session.userId]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Tag name already exists' });
    res.status(500).json({ error: 'Failed to create tag' });
  }
});

app.put('/api/tags/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const { name, color } = req.body;
    const result = await query('UPDATE tags SET name = COALESCE($1, name), color = COALESCE($2, color) WHERE id = $3 RETURNING *', [name, color, req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tag not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update tag' }); }
});

app.delete('/api/tags/:id', requireAdmin, validateId, async (req, res) => {
  try {
    await query('DELETE FROM tags WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete tag' }); }
});

// ─── Domains ───
app.get('/api/domains', requireAuth, async (req, res) => {
  try {
    const tag = req.query.tag;
    let sql = `
      SELECT d.*,
        (SELECT COUNT(*) FROM dns_records WHERE domain_id = d.id AND removed_at IS NULL) as record_count,
        (SELECT COUNT(*) FROM dns_records dr
          JOIN health_checks hc ON hc.id = (SELECT id FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1)
          WHERE dr.domain_id = d.id AND dr.removed_at IS NULL AND hc.status = 'dead') as dead_count,
        (SELECT started_at FROM scans WHERE domain_id = d.id ORDER BY started_at DESC LIMIT 1) as last_scan,
        COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'color', t.color))
          FROM tags t JOIN domain_tags dt ON dt.tag_id = t.id WHERE dt.domain_id = d.id), '[]') as tags
      FROM domains d
    `;
    const params = [];
    if (tag) {
      sql += ` WHERE d.id IN (SELECT domain_id FROM domain_tags dt JOIN tags t ON t.id = dt.tag_id WHERE t.name = $1)`;
      params.push(tag);
    }
    sql += ' ORDER BY d.domain';
    const result = await query(sql, params);
    res.json(result.rows);
  } catch (err) {
    console.error('[DOMAINS] List error:', err.message);
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
});

app.post('/api/domains', requireAdmin, async (req, res) => {
  try {
    const { domain, display_name, scan_interval_minutes } = req.body;
    if (!validateDomain(domain)) return res.status(400).json({ error: 'Invalid domain format' });
    const maxDomains = parseInt(process.env.MAX_DOMAINS || '50', 10);
    const countResult = await query('SELECT COUNT(*) as count FROM domains');
    if (parseInt(countResult.rows[0].count) >= maxDomains) return res.status(400).json({ error: `Max ${maxDomains} domains allowed` });
    const interval = Math.max(15, Math.min(10080, parseInt(scan_interval_minutes) || 360));
    const result = await query(
      'INSERT INTO domains (domain, display_name, scan_interval_minutes, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
      [domain.toLowerCase(), display_name || null, interval, req.session.userId]
    );
    console.log(`[DOMAINS] Added: ${domain} by user ${req.session.userId}`);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Domain already exists' });
    res.status(500).json({ error: 'Failed to add domain' });
  }
});

app.put('/api/domains/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const { display_name, scan_interval_minutes, enabled } = req.body;
    const interval = scan_interval_minutes ? Math.max(15, Math.min(10080, parseInt(scan_interval_minutes))) : undefined;
    const result = await query(
      `UPDATE domains SET
        display_name = COALESCE($1, display_name),
        scan_interval_minutes = COALESCE($2, scan_interval_minutes),
        enabled = COALESCE($3, enabled),
        updated_at = NOW()
      WHERE id = $4 RETURNING *`,
      [display_name, interval, enabled, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update domain' }); }
});

app.delete('/api/domains/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const result = await query('DELETE FROM domains WHERE id = $1 RETURNING domain', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });
    console.log(`[DOMAINS] Deleted: ${result.rows[0].domain} by user ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete domain' }); }
});

// Domain tags
app.post('/api/domains/:id/tags/:tagId', requireAdmin, async (req, res) => {
  try {
    const domainId = parseInt(req.params.id, 10);
    const tagId = parseInt(req.params.tagId, 10);
    if (!Number.isInteger(domainId) || domainId < 1 || !Number.isInteger(tagId) || tagId < 1) return res.status(400).json({ error: 'Invalid IDs' });
    await query('INSERT INTO domain_tags (domain_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [domainId, tagId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to add tag' }); }
});

app.delete('/api/domains/:id/tags/:tagId', requireAdmin, async (req, res) => {
  try {
    const domainId = parseInt(req.params.id, 10);
    const tagId = parseInt(req.params.tagId, 10);
    if (!Number.isInteger(domainId) || domainId < 1 || !Number.isInteger(tagId) || tagId < 1) return res.status(400).json({ error: 'Invalid IDs' });
    await query('DELETE FROM domain_tags WHERE domain_id = $1 AND tag_id = $2', [domainId, tagId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to remove tag' }); }
});

// Bulk import
app.post('/api/domains/import', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'CSV file required' });
    const csv = req.file.buffer.toString('utf8');
    const lines = csv.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('domain,'));
    if (lines.length > 100) return res.status(400).json({ error: 'Max 100 domains per import' });

    const results = { imported: 0, skipped: 0, errors: [] };
    for (const line of lines) {
      const parts = line.split(',').map(p => p.trim());
      const domain = parts[0]?.toLowerCase();
      if (!validateDomain(domain)) { results.errors.push(`Invalid: ${parts[0]}`); results.skipped++; continue; }
      try {
        const interval = Math.max(15, Math.min(10080, parseInt(parts[2]) || 360));
        await query(
          'INSERT INTO domains (domain, display_name, scan_interval_minutes, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (domain) DO NOTHING',
          [domain, parts[1] || null, interval, req.session.userId]
        );
        results.imported++;
        if (parts[3]) {
          const tagNames = parts[3].split(';').map(t => t.trim()).filter(Boolean);
          for (const tagName of tagNames) {
            const tagResult = await query('INSERT INTO tags (name, created_by) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id', [tagName, req.session.userId]);
            const domainResult = await query('SELECT id FROM domains WHERE domain = $1', [domain]);
            if (domainResult.rows.length && tagResult.rows.length) {
              await query('INSERT INTO domain_tags (domain_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [domainResult.rows[0].id, tagResult.rows[0].id]);
            }
          }
        }
      } catch (err) { results.errors.push(`Error: ${domain} - ${err.message}`); results.skipped++; }
    }
    console.log(`[DOMAINS] Bulk import: ${results.imported} imported, ${results.skipped} skipped`);
    res.json(results);
  } catch (err) { res.status(500).json({ error: 'Import failed' }); }
});

// ─── Scanning ───
app.post('/api/domains/:id/scan', requireAuth, scanLimiter, validateId, async (req, res) => {
  try {
    const domainResult = await query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domainResult.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });
    const running = await query('SELECT id FROM scans WHERE domain_id = $1 AND status = $2', [req.params.id, SCAN_STATUS.RUNNING]);
    if (running.rows.length > 0) return res.status(409).json({ error: 'Scan already running' });
    const scanResult = await query(
      'INSERT INTO scans (domain_id, trigger, triggered_by) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, SCAN_TRIGGER.MANUAL, req.session.userId]
    );
    console.log(`[SCAN] Manual scan started for ${domainResult.rows[0].domain} by user ${req.session.userId}`);
    // Scan runs asynchronously
    const { performScan } = require('./scanner');
    performScan(domainResult.rows[0], scanResult.rows[0].id).catch(err => {
      console.error(`[SCAN] Error:`, err.message);
    });
    broadcastSSE({ type: 'scan_started', domainId: req.params.id, scanId: scanResult.rows[0].id });
    res.json(scanResult.rows[0]);
  } catch (err) {
    console.error('[SCAN] Error:', err.message);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

app.post('/api/scan-all', requireAuth, scanLimiter, async (req, res) => {
  try {
    const domains = await query('SELECT * FROM domains WHERE enabled = TRUE');
    const { performScan } = require('./scanner');
    let started = 0;
    const pending = [];
    for (const domain of domains.rows) {
      const running = await query('SELECT id FROM scans WHERE domain_id = $1 AND status = $2', [domain.id, SCAN_STATUS.RUNNING]);
      if (running.rows.length > 0) continue;
      const scanResult = await query(
        'INSERT INTO scans (domain_id, trigger, triggered_by) VALUES ($1, $2, $3) RETURNING id',
        [domain.id, SCAN_TRIGGER.MANUAL, req.session.userId]
      );
      const p = performScan(domain, scanResult.rows[0].id).catch(err => console.error(`[SCAN] Error scanning ${domain.domain}:`, err.message));
      pending.push(p);
      started++;
      // Limit concurrency: wait for batch of 5 before starting more
      if (pending.length >= 5) {
        await Promise.race(pending);
        // Remove settled promises
        for (let i = pending.length - 1; i >= 0; i--) {
          const settled = await Promise.race([pending[i].then(() => true, () => true), Promise.resolve(false)]);
          if (settled) pending.splice(i, 1);
        }
      }
    }
    broadcastSSE({ type: 'scan_all_started', count: started });
    res.json({ started, total: domains.rows.length });
  } catch (err) { res.status(500).json({ error: 'Failed to start scans' }); }
});

app.get('/api/domains/:id/scans', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM scans WHERE domain_id = $1 ORDER BY started_at DESC LIMIT 50', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch scans' }); }
});

app.get('/api/scans/:id', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM scans WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Scan not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch scan' }); }
});

// ─── Records & Health ───
app.get('/api/domains/:id/records', requireAuth, validateId, async (req, res) => {
  try {
    const status = req.query.status;
    let sql = `
      SELECT dr.*,
        (SELECT row_to_json(hc) FROM (
          SELECT status, status_code, response_ms, error_message, check_method, ports_open, ssl_valid, ssl_expires_at, ssl_error, propagation_results, checked_at
          FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1
        ) hc) as latest_health,
        (SELECT COUNT(*) FROM health_checks WHERE record_id = dr.id AND status = 'dead') as consecutive_failures
      FROM dns_records dr
      WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
    `;
    const params = [req.params.id];

    if (status === 'dead') {
      sql += ` AND dr.id IN (SELECT record_id FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) AND (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) = 'dead'`;
    } else if (status === 'alive') {
      sql += ` AND (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) = 'alive'`;
    } else if (status === 'new') {
      sql += ` AND dr.first_seen > NOW() - INTERVAL '24 hours'`;
    } else if (status === 'changed') {
      sql += ` AND dr.id IN (SELECT record_id FROM dns_changes WHERE domain_id = $1 AND changed_at > NOW() - INTERVAL '24 hours')`;
    }

    sql += ' ORDER BY dr.record_type, dr.name';
    const result = await query(sql, params);
    res.json(result.rows);
  } catch (err) {
    console.error('[RECORDS] Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch records' });
  }
});

app.get('/api/records/:id/history', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM health_checks WHERE record_id = $1 ORDER BY checked_at DESC LIMIT 100', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch history' }); }
});

app.get('/api/records/:id/changes', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM dns_changes WHERE record_id = $1 ORDER BY changed_at DESC LIMIT 50', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch changes' }); }
});

app.get('/api/domains/:id/changes', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM dns_changes WHERE domain_id = $1 ORDER BY changed_at DESC LIMIT 100', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch changes' }); }
});

app.put('/api/records/:id/dismiss', requireAuth, validateId, async (req, res) => {
  try {
    await query('UPDATE dns_records SET dismissed = $1, dismissed_by = $2 WHERE id = $3', [req.body.dismissed !== false, req.session.userId, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to dismiss record' }); }
});

// ─── Dashboard ───
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const tag = req.query.tag;
    let domainFilter = '';
    const params = [];
    if (tag) {
      domainFilter = `AND d.id IN (SELECT domain_id FROM domain_tags dt JOIN tags t ON t.id = dt.tag_id WHERE t.name = $1)`;
      params.push(tag);
    }

    const stats = await query(`
      SELECT
        (SELECT COUNT(*) FROM domains d WHERE enabled = TRUE ${domainFilter}) as total_domains,
        (SELECT COUNT(*) FROM dns_records dr JOIN domains d ON d.id = dr.domain_id WHERE dr.removed_at IS NULL ${domainFilter}) as total_records
    `, params);

    const deadRecords = await query(`
      SELECT dr.*, d.domain, d.display_name,
        hc.status, hc.checked_at, hc.error_message, hc.ports_open
      FROM dns_records dr
      JOIN domains d ON d.id = dr.domain_id
      JOIN LATERAL (
        SELECT * FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1
      ) hc ON TRUE
      WHERE dr.removed_at IS NULL AND dr.dismissed = FALSE
        AND hc.status IN ('dead', 'takeover_risk')
        ${domainFilter}
      ORDER BY hc.status = 'takeover_risk' DESC, hc.checked_at DESC
      LIMIT 50
    `, params);

    const recentChanges = await query(`
      SELECT dc.*, d.domain FROM dns_changes dc
      JOIN domains d ON d.id = dc.domain_id
      ${domainFilter ? `WHERE d.id IN (SELECT domain_id FROM domain_tags dt JOIN tags t ON t.id = dt.tag_id WHERE t.name = $1)` : ''}
      ORDER BY dc.changed_at DESC LIMIT 20
    `, params);

    const aliveCount = await query(`
      SELECT COUNT(DISTINCT dr.id) as count
      FROM dns_records dr
      JOIN domains d ON d.id = dr.domain_id
      JOIN LATERAL (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) hc ON TRUE
      WHERE dr.removed_at IS NULL AND hc.status = 'alive' ${domainFilter}
    `, params);

    res.json({
      total_domains: parseInt(stats.rows[0].total_domains),
      total_records: parseInt(stats.rows[0].total_records),
      alive_records: parseInt(aliveCount.rows[0].count),
      dead_records: deadRecords.rows,
      recent_changes: recentChanges.rows,
    });
  } catch (err) {
    console.error('[DASHBOARD] Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch dashboard' });
  }
});

// ─── Export ───
app.get('/api/domains/:id/export/csv', requireAuth, validateId, async (req, res) => {
  try {
    const domain = await query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domain.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });

    const records = await query(`
      SELECT dr.record_type, dr.name, dr.value, dr.priority, dr.ttl, dr.first_seen, dr.last_seen,
        (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as health_status,
        (SELECT response_ms FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as response_ms
      FROM dns_records dr WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
      ORDER BY dr.record_type, dr.name
    `, [req.params.id]);

    let csv = 'Type,Name,Value,Priority,TTL,Status,Response(ms),First Seen,Last Seen\n';
    for (const r of records.rows) {
      csv += `${r.record_type},${r.name},"${escapeCsv(r.value)}",${r.priority || ''},${r.ttl || ''},${r.health_status || 'unknown'},${r.response_ms || ''},${r.first_seen},${r.last_seen}\n`;
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${domain.rows[0].domain}-records.csv"`);
    res.send(csv);
  } catch (err) { res.status(500).json({ error: 'Export failed' }); }
});

app.get('/api/domains/:id/export/report', requireAuth, validateId, async (req, res) => {
  try {
    const domain = await query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domain.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });

    const records = await query(`
      SELECT dr.*,
        (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as health_status,
        (SELECT response_ms FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as response_ms,
        (SELECT ssl_valid FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as ssl_valid,
        (SELECT ssl_expires_at FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as ssl_expires_at
      FROM dns_records dr WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
      ORDER BY dr.record_type, dr.name
    `, [req.params.id]);

    const d = domain.rows[0];
    const alive = records.rows.filter(r => r.health_status === 'alive').length;
    const dead = records.rows.filter(r => r.health_status === 'dead').length;

    let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>DNS Report: ${escapeHtml(d.domain)}</title>
    <style>
      body{font-family:-apple-system,sans-serif;max-width:900px;margin:0 auto;padding:20px;color:#333}
      h1{border-bottom:2px solid #333;padding-bottom:10px}
      .summary{display:flex;gap:20px;margin:20px 0}
      .stat{padding:15px;border-radius:8px;text-align:center;min-width:100px}
      .stat-alive{background:#dcfce7;color:#166534} .stat-dead{background:#fef2f2;color:#991b1b}
      .stat h2{margin:0;font-size:28px} .stat p{margin:5px 0 0}
      table{width:100%;border-collapse:collapse;margin:20px 0}
      th,td{border:1px solid #ddd;padding:8px 12px;text-align:left}
      th{background:#f9fafb;font-weight:600}
      .status-alive{color:#16a34a;font-weight:600} .status-dead{color:#dc2626;font-weight:600}
      .status-skipped{color:#9ca3af} .status-takeover_risk{color:#7c3aed;font-weight:600}
      @media print{body{padding:0} .no-print{display:none}}
    </style></head><body>
    <h1>DNS Report: ${escapeHtml(d.display_name || d.domain)}</h1>
    <p>Generated: ${new Date().toISOString()}</p>
    <div class="summary">
      <div class="stat stat-alive"><h2>${alive}</h2><p>Alive</p></div>
      <div class="stat stat-dead"><h2>${dead}</h2><p>Dead</p></div>
      <div class="stat"><h2>${records.rows.length}</h2><p>Total</p></div>
    </div>
    <table><thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Status</th><th>Response</th><th>SSL</th></tr></thead><tbody>`;

    for (const r of records.rows) {
      const statusClass = `status-${r.health_status || 'unknown'}`;
      html += `<tr><td>${escapeHtml(r.record_type)}</td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.value)}</td>
        <td class="${statusClass}">${(r.health_status || 'unknown').toUpperCase()}</td>
        <td>${r.response_ms ? r.response_ms + 'ms' : '-'}</td>
        <td>${r.ssl_valid === true ? 'Valid' : r.ssl_valid === false ? 'Invalid' : '-'}</td></tr>`;
    }

    html += `</tbody></table>
    <button class="no-print" onclick="window.print()" style="padding:10px 20px;background:#3b82f6;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:16px">Print / Save PDF</button>
    </body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) { res.status(500).json({ error: 'Report generation failed' }); }
});

function escapeCsv(val) {
  if (!val) return '';
  const s = String(val);
  if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
  return s;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── Notification settings ───
app.get('/api/notifications/settings', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM notification_settings WHERE user_id = $1', [req.session.userId]);
    if (result.rows.length === 0) {
      await query('INSERT INTO notification_settings (user_id) VALUES ($1)', [req.session.userId]);
      return res.json({ user_id: req.session.userId, email_enabled: false, push_enabled: false, notify_on_dead: true, notify_on_recovery: true, notify_on_takeover_risk: true, notify_on_dns_change: true, notify_on_domain_expiry: true, notify_tags_only: null });
    }
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch settings' }); }
});

app.put('/api/notifications/settings', requireAuth, async (req, res) => {
  try {
    const { email_enabled, push_enabled, notify_on_dead, notify_on_recovery, notify_on_takeover_risk, notify_on_dns_change, notify_on_domain_expiry, notify_tags_only } = req.body;
    await query(`
      INSERT INTO notification_settings (user_id, email_enabled, push_enabled, notify_on_dead, notify_on_recovery, notify_on_takeover_risk, notify_on_dns_change, notify_on_domain_expiry, notify_tags_only)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (user_id) DO UPDATE SET
        email_enabled = COALESCE($2, notification_settings.email_enabled),
        push_enabled = COALESCE($3, notification_settings.push_enabled),
        notify_on_dead = COALESCE($4, notification_settings.notify_on_dead),
        notify_on_recovery = COALESCE($5, notification_settings.notify_on_recovery),
        notify_on_takeover_risk = COALESCE($6, notification_settings.notify_on_takeover_risk),
        notify_on_dns_change = COALESCE($7, notification_settings.notify_on_dns_change),
        notify_on_domain_expiry = COALESCE($8, notification_settings.notify_on_domain_expiry),
        notify_tags_only = COALESCE($9, notification_settings.notify_tags_only)
    `, [req.session.userId, email_enabled, push_enabled, notify_on_dead, notify_on_recovery, notify_on_takeover_risk, notify_on_dns_change, notify_on_domain_expiry, notify_tags_only ? JSON.stringify(notify_tags_only) : null]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update settings' }); }
});

// ─── Push notifications ───
app.get('/api/push/vapid-key', requireAuth, async (req, res) => {
  try {
    const { getVapidPublicKey } = require('./notifier');
    const key = await getVapidPublicKey();
    res.json({ publicKey: key });
  } catch (err) { res.status(500).json({ error: 'Failed to get VAPID key' }); }
});

app.post('/api/push/subscribe', requireAuth, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys?.p256dh || !keys?.auth) return res.status(400).json({ error: 'Invalid subscription' });
    await query('DELETE FROM push_subscriptions WHERE user_id = $1 AND endpoint = $2', [req.session.userId, endpoint]);
    await query('INSERT INTO push_subscriptions (user_id, endpoint, keys_p256dh, keys_auth) VALUES ($1, $2, $3, $4)',
      [req.session.userId, endpoint, keys.p256dh, keys.auth]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to subscribe' }); }
});

app.delete('/api/push/subscribe', requireAuth, async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (endpoint) {
      await query('DELETE FROM push_subscriptions WHERE user_id = $1 AND endpoint = $2', [req.session.userId, endpoint]);
    } else {
      await query('DELETE FROM push_subscriptions WHERE user_id = $1', [req.session.userId]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to unsubscribe' }); }
});

app.post('/api/notifications/test-push', requireAuth, async (req, res) => {
  try {
    const { sendPushToUser } = require('./notifier');
    await sendPushToUser(req.session.userId, { title: 'DNS Scanner', body: 'Test push notification!' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to send test push: ' + err.message }); }
});

app.post('/api/notifications/test-email', requireAuth, async (req, res) => {
  try {
    const user = await query('SELECT email FROM users WHERE id = $1', [req.session.userId]);
    if (!user.rows[0]?.email) return res.status(400).json({ error: 'No email address configured' });
    const { sendEmail } = require('./notifier');
    await sendEmail(user.rows[0].email, 'DNS Scanner - Test Email', '<h1>Test Email</h1><p>This is a test email from DNS Scanner.</p>');
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to send test email: ' + err.message }); }
});

// ─── SMTP config (admin) ───
app.get('/api/smtp', requireAdmin, async (req, res) => {
  try {
    const result = await query('SELECT id, smtp_host, smtp_port, smtp_user, smtp_secure FROM smtp_config LIMIT 1');
    res.json(result.rows[0] || {});
  } catch (err) { res.status(500).json({ error: 'Failed to fetch SMTP config' }); }
});

app.put('/api/smtp', requireAdmin, async (req, res) => {
  try {
    const { smtp_host, smtp_port, smtp_user, smtp_pass, smtp_secure } = req.body;
    if (!smtp_host || !smtp_pass) return res.status(400).json({ error: 'SMTP host and password required' });
    const encryptedPass = encrypt(smtp_pass);
    await query('DELETE FROM smtp_config');
    await query('INSERT INTO smtp_config (smtp_host, smtp_port, smtp_user, smtp_pass, smtp_secure) VALUES ($1, $2, $3, $4, $5)',
      [smtp_host, smtp_port || 587, smtp_user || '', encryptedPass, smtp_secure !== false]);
    console.log(`[SMTP] Config updated by admin ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update SMTP config' }); }
});

// ─── Webhooks (admin) ───
app.get('/api/webhooks', requireAdmin, async (req, res) => {
  try {
    const result = await query('SELECT id, name, url, events, enabled, created_at FROM webhooks WHERE created_by = $1 ORDER BY created_at DESC', [req.session.userId]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch webhooks' }); }
});

app.post('/api/webhooks', requireAdmin, async (req, res) => {
  try {
    const { name, url, secret, events, enabled } = req.body;
    if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
    if (events && !Array.isArray(events)) return res.status(400).json({ error: 'Events must be an array' });
    const webhookSecret = secret || crypto.randomBytes(32).toString('hex');
    const result = await query(
      'INSERT INTO webhooks (created_by, name, url, secret, events, enabled) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, url, events, enabled, created_at',
      [req.session.userId, name, url, webhookSecret, JSON.stringify(events || WEBHOOK_EVENT_TYPES), enabled !== false]
    );
    res.status(201).json({ ...result.rows[0], secret: webhookSecret });
  } catch (err) { res.status(500).json({ error: 'Failed to create webhook' }); }
});

app.put('/api/webhooks/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const { name, url, events, enabled } = req.body;
    const result = await query(
      `UPDATE webhooks SET name = COALESCE($1, name), url = COALESCE($2, url), events = COALESCE($3, events), enabled = COALESCE($4, enabled) WHERE id = $5 AND created_by = $6 RETURNING id, name, url, events, enabled`,
      [name, url, events ? JSON.stringify(events) : null, enabled, req.params.id, req.session.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Webhook not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update webhook' }); }
});

app.delete('/api/webhooks/:id', requireAdmin, validateId, async (req, res) => {
  try {
    await query('DELETE FROM webhooks WHERE id = $1 AND created_by = $2', [req.params.id, req.session.userId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete webhook' }); }
});

app.post('/api/webhooks/:id/test', requireAdmin, validateId, async (req, res) => {
  try {
    const wh = await query('SELECT * FROM webhooks WHERE id = $1 AND created_by = $2', [req.params.id, req.session.userId]);
    if (wh.rows.length === 0) return res.status(404).json({ error: 'Webhook not found' });
    const { deliverWebhook } = require('./notifier');
    await deliverWebhook(wh.rows[0], 'scan.completed', { test: true, message: 'Test webhook delivery from DNS Scanner' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to send test webhook: ' + err.message }); }
});

app.get('/api/webhooks/:id/deliveries', requireAdmin, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY delivered_at DESC LIMIT 50', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch deliveries' }); }
});

// ─── Propagation ───
app.get('/api/domains/:id/propagation', requireAuth, validateId, async (req, res) => {
  try {
    const records = await query(`
      SELECT dr.id, dr.record_type, dr.name, dr.value, hc.propagation_results
      FROM dns_records dr
      LEFT JOIN LATERAL (SELECT propagation_results FROM health_checks WHERE record_id = dr.id AND propagation_results IS NOT NULL ORDER BY checked_at DESC LIMIT 1) hc ON TRUE
      WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
      ORDER BY dr.record_type, dr.name
    `, [req.params.id]);
    res.json(records.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch propagation data' }); }
});

// ─── Whois ───
app.get('/api/domains/:id/whois', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT dw.*, d.domain FROM domain_whois dw JOIN domains d ON d.id = dw.domain_id WHERE dw.domain_id = $1', [req.params.id]);
    res.json(result.rows[0] || null);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch whois data' }); }
});

// ─── SSE ───
app.get('/api/events', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const clientId = Date.now() + '_' + req.session.userId;
  sseClients.set(clientId, res);

  const cleanup = () => {
    clearInterval(heartbeat);
    clearTimeout(autoDisconnect);
    sseClients.delete(clientId);
  };

  const heartbeat = setInterval(() => {
    try { res.write(':heartbeat\n\n'); } catch (e) { cleanup(); }
  }, 30000);

  const autoDisconnect = setTimeout(() => {
    cleanup();
    try { res.end(); } catch (e) {}
  }, 60 * 60 * 1000);

  req.on('close', cleanup);
});

function broadcastSSE(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const [, client] of sseClients) {
    try { client.write(msg); } catch (e) { /* ignore */ }
  }
}

// ─── SPA fallback ───
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Error handler ───
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Bootstrap ───
// Session and routes must be set up before listen, but after DB init.
// Express uses a router internally — middleware added via app.use applies
// to all subsequent requests regardless of when routes were defined,
// as long as middleware is registered before listen().
async function start() {
  validateEnv();
  await initSchema();
  setupSession();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SERVER] DNS Scanner running on port ${PORT}`);
  });
}

start().catch(err => {
  console.error('[FATAL]', err.message);
  process.exit(1);
});

module.exports = { app, broadcastSSE };
