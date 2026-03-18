'use strict';
const router = require('express').Router();
const { query } = require('../db');
const { requireAdmin, requireAuth, logAudit } = require('../middleware');
const { getAllSettings, setSetting, SETTINGS_DEFINITIONS } = require('../settings-service');

// ─── Toggle Google auth (legacy endpoint, uses settings service) ───
router.put('/google-auth', requireAdmin, async (req, res) => {
  try {
    const { enabled } = req.body;
    await setSetting('google_auth_enabled', String(enabled));
    logAudit(req, 'settings.google_auth', 'app_settings', null, { enabled });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update setting' }); }
});

// ─── System settings (all configurable settings) ───
router.get('/system', requireAdmin, async (req, res) => {
  try {
    const settings = await getAllSettings();
    res.json(settings);
  } catch (err) {
    console.error('[SETTINGS] Error loading system settings:', err.message);
    res.status(500).json({ error: 'Failed to load system settings' });
  }
});

router.put('/system', requireAdmin, async (req, res) => {
  try {
    const updates = req.body;
    if (!updates || typeof updates !== 'object') {
      return res.status(400).json({ error: 'Request body must be an object of key-value pairs' });
    }

    const updated = [];
    for (const [key, value] of Object.entries(updates)) {
      if (!SETTINGS_DEFINITIONS[key]) continue;
      // Skip empty strings for sensitive fields (means "keep current")
      if (SETTINGS_DEFINITIONS[key].sensitive && !value) continue;
      await setSetting(key, String(value));
      updated.push(key);
    }

    logAudit(req, 'settings.system_update', 'app_settings', null, { keys: updated });
    res.json({ ok: true, updated });
  } catch (err) {
    console.error('[SETTINGS] Error updating system settings:', err.message);
    res.status(500).json({ error: err.message || 'Failed to update system settings' });
  }
});

// ─── Audit log ───
router.get('/audit-log', requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
    const offset = (page - 1) * limit;
    const action = req.query.action || null;
    const userId = req.query.user_id ? parseInt(req.query.user_id) : null;

    let sql = `
      SELECT al.*, u.username
      FROM audit_log al
      LEFT JOIN users u ON u.id = al.user_id
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    if (action) {
      sql += ` AND al.action = $${paramIndex}`;
      params.push(action);
      paramIndex++;
    }

    if (userId) {
      sql += ` AND al.user_id = $${paramIndex}`;
      params.push(userId);
      paramIndex++;
    }

    sql += ` ORDER BY al.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);

    const result = await query(sql, params);

    // Get total count for pagination
    let countSql = 'SELECT COUNT(*) as total FROM audit_log al WHERE 1=1';
    const countParams = [];
    let countIndex = 1;
    if (action) {
      countSql += ` AND al.action = $${countIndex}`;
      countParams.push(action);
      countIndex++;
    }
    if (userId) {
      countSql += ` AND al.user_id = $${countIndex}`;
      countParams.push(userId);
      countIndex++;
    }
    const countResult = await query(countSql, countParams);

    res.json({
      entries: result.rows,
      total: parseInt(countResult.rows[0].total),
      page,
      limit,
    });
  } catch (err) {
    console.error('[AUDIT] Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// ─── Worker status ───
router.get('/worker/status', requireAuth, async (req, res) => {
  try {
    const result = await query("SELECT key, value FROM app_settings WHERE key IN ('worker_last_run', 'worker_last_scan', 'worker_last_health_check')");
    const status = {};
    for (const row of result.rows) {
      status[row.key] = row.value;
    }
    res.json(status);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch worker status' }); }
});

module.exports = router;
