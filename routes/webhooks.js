'use strict';
const router = require('express').Router();
const crypto = require('node:crypto');
const { query } = require('../db');
const { requireAdmin, validateId, logAudit } = require('../middleware');
const { WEBHOOK_EVENT_TYPES } = require('../constants');

// ─── List webhooks ───
router.get('/', requireAdmin, async (req, res) => {
  try {
    const result = await query('SELECT id, name, url, events, enabled, created_at FROM webhooks WHERE created_by = $1 ORDER BY created_at DESC', [req.session.userId]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch webhooks' }); }
});

// ─── Create webhook ───
router.post('/', requireAdmin, async (req, res) => {
  try {
    const { name, url, secret, events, enabled } = req.body;
    if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
    if (events && !Array.isArray(events)) return res.status(400).json({ error: 'Events must be an array' });
    const webhookSecret = secret || crypto.randomBytes(32).toString('hex');
    const result = await query(
      'INSERT INTO webhooks (created_by, name, url, secret, events, enabled) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, url, events, enabled, created_at',
      [req.session.userId, name, url, webhookSecret, JSON.stringify(events || WEBHOOK_EVENT_TYPES), enabled !== false]
    );
    logAudit(req, 'webhook.create', 'webhook', result.rows[0].id);
    res.status(201).json({ ...result.rows[0], secret: webhookSecret });
  } catch (err) { res.status(500).json({ error: 'Failed to create webhook' }); }
});

// ─── Update webhook ───
router.put('/:id', requireAdmin, validateId, async (req, res) => {
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

// ─── Delete webhook ───
router.delete('/:id', requireAdmin, validateId, async (req, res) => {
  try {
    await query('DELETE FROM webhooks WHERE id = $1 AND created_by = $2', [req.params.id, req.session.userId]);
    logAudit(req, 'webhook.delete', 'webhook', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete webhook' }); }
});

// ─── Test webhook ───
router.post('/:id/test', requireAdmin, validateId, async (req, res) => {
  try {
    const wh = await query('SELECT * FROM webhooks WHERE id = $1 AND created_by = $2', [req.params.id, req.session.userId]);
    if (wh.rows.length === 0) return res.status(404).json({ error: 'Webhook not found' });
    const { deliverWebhook } = require('../notifier');
    await deliverWebhook(wh.rows[0], 'scan.completed', { test: true, message: 'Test webhook delivery from DNS Scanner' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to send test webhook: ' + err.message }); }
});

// ─── Delivery history ───
router.get('/:id/deliveries', requireAdmin, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY delivered_at DESC LIMIT 50', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch deliveries' }); }
});

module.exports = router;
