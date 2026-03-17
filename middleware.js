'use strict';

const crypto = require('node:crypto');
const { query } = require('./db');
const { USER_ROLES, DOMAIN_REGEX } = require('./constants');

// ─── Auth middleware ───
function requireAuth(req, res, next) {
  // Check session auth
  if (req.session?.userId) return next();
  // Check API key auth
  const authHeader = req.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const key = authHeader.slice(7);
    const keyHash = crypto.createHash('sha256').update(key).digest('hex');
    query('SELECT ak.*, u.role FROM api_keys ak JOIN users u ON u.id = ak.user_id WHERE ak.key_hash = $1', [keyHash])
      .then(result => {
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid API key' });
        const ak = result.rows[0];
        req.session = req.session || {};
        req.apiKeyAuth = true;
        req.session.userId = ak.user_id;
        req.session.role = ak.role;
        query('UPDATE api_keys SET last_used_at = NOW() WHERE id = $1', [ak.id]).catch(() => {});
        next();
      })
      .catch(() => res.status(500).json({ error: 'Auth error' }));
    return;
  }
  return res.status(401).json({ error: 'Authentication required' });
}

function requireAdmin(req, res, next) {
  // First ensure authenticated
  requireAuth(req, res, () => {
    if (req.session.role !== USER_ROLES.ADMIN) return res.status(403).json({ error: 'Admin access required' });
    next();
  });
}

// ─── Input validation ───
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

// ─── CSRF protection ───
function csrfProtect(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!req.path.startsWith('/api/')) return next();
  // Allow API key authenticated requests (no CSRF needed)
  if (req.apiKeyAuth) return next();
  // Allow Google OAuth callback
  if (req.path === '/api/auth/google/callback') return next();

  const ct = req.get('content-type') || '';
  // Allow JSON and multipart (file uploads)
  if (!ct.includes('application/json') && !ct.includes('multipart/form-data') && ct !== '') {
    return res.status(415).json({ error: 'Unsupported content type' });
  }

  // Validate Origin header if present
  const origin = req.get('origin');
  if (origin) {
    const proto = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('x-forwarded-host') || req.get('host');
    const expected = `${proto}://${host}`;
    if (origin !== expected) {
      return res.status(403).json({ error: 'Invalid origin' });
    }
  }
  next();
}

// ─── Tag-based access control ───
// Accepts either (req) or (userId, role)
async function getTagFilter(reqOrUserId, role) {
  let userId, userRole;
  if (typeof reqOrUserId === 'object' && reqOrUserId.session) {
    userId = reqOrUserId.session.userId;
    userRole = reqOrUserId.session.role;
  } else {
    userId = reqOrUserId;
    userRole = role;
  }
  if (userRole === USER_ROLES.ADMIN) return { clause: '', params: [] };
  const result = await query('SELECT allowed_tags FROM users WHERE id = $1', [userId]);
  const allowedTags = result.rows[0]?.allowed_tags;
  if (!allowedTags || allowedTags.length === 0) return { clause: '', params: [] };
  return {
    clause: 'd.id IN (SELECT domain_id FROM domain_tags WHERE tag_id = ANY($TAG_PARAM))',
    params: [allowedTags],
  };
}

// ─── Audit logging ───
async function logAudit(req, action, targetType, targetId, details) {
  try {
    const ip = req.ip || req.connection?.remoteAddress || null;
    await query(
      'INSERT INTO audit_log (user_id, action, target_type, target_id, details, ip) VALUES ($1, $2, $3, $4, $5, $6)',
      [req.session?.userId || null, action, targetType || null, targetId || null, details ? JSON.stringify(details) : null, ip]
    );
  } catch (err) {
    console.error('[AUDIT] Log error:', err.message);
  }
}

// ─── HTML/CSV escaping ───
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeCsv(val) {
  if (!val) return '';
  const s = String(val);
  if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
  return s;
}

module.exports = {
  requireAuth,
  requireAdmin,
  validateId,
  validateDomain,
  csrfProtect,
  getTagFilter,
  logAudit,
  escapeHtml,
  escapeCsv,
};
