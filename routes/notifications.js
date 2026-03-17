'use strict';
const router = require('express').Router();
const { query } = require('../db');
const { requireAuth, requireAdmin, logAudit } = require('../middleware');
const { encrypt } = require('../crypto-utils');

// ─── Get notification settings ───
router.get('/notifications/settings', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM notification_settings WHERE user_id = $1', [req.session.userId]);
    if (result.rows.length === 0) {
      await query('INSERT INTO notification_settings (user_id) VALUES ($1)', [req.session.userId]);
      return res.json({ user_id: req.session.userId, email_enabled: false, push_enabled: false, notify_on_dead: true, notify_on_recovery: true, notify_on_takeover_risk: true, notify_on_dns_change: true, notify_on_domain_expiry: true, notify_tags_only: null });
    }
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch settings' }); }
});

// ─── Update notification settings ───
router.put('/notifications/settings', requireAuth, async (req, res) => {
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

// ─── VAPID public key ───
router.get('/push/vapid-key', requireAuth, async (req, res) => {
  try {
    const { getVapidPublicKey } = require('../notifier');
    const key = await getVapidPublicKey();
    res.json({ publicKey: key });
  } catch (err) { res.status(500).json({ error: 'Failed to get VAPID key' }); }
});

// ─── Push subscribe ───
router.post('/push/subscribe', requireAuth, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys?.p256dh || !keys?.auth) return res.status(400).json({ error: 'Invalid subscription' });
    await query('DELETE FROM push_subscriptions WHERE user_id = $1 AND endpoint = $2', [req.session.userId, endpoint]);
    await query('INSERT INTO push_subscriptions (user_id, endpoint, keys_p256dh, keys_auth) VALUES ($1, $2, $3, $4)',
      [req.session.userId, endpoint, keys.p256dh, keys.auth]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to subscribe' }); }
});

// ─── Push unsubscribe ───
router.delete('/push/subscribe', requireAuth, async (req, res) => {
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

// ─── Test push ───
router.post('/notifications/test-push', requireAuth, async (req, res) => {
  try {
    const { sendPushToUser } = require('../notifier');
    await sendPushToUser(req.session.userId, { title: 'DNS Scanner', body: 'Test push notification!' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to send test push: ' + err.message }); }
});

// ─── Test email ───
router.post('/notifications/test-email', requireAuth, async (req, res) => {
  try {
    const user = await query('SELECT email FROM users WHERE id = $1', [req.session.userId]);
    if (!user.rows[0]?.email) return res.status(400).json({ error: 'No email address configured' });
    const { sendEmail } = require('../notifier');
    await sendEmail(user.rows[0].email, 'DNS Scanner - Test Email', '<h1>Test Email</h1><p>This is a test email from DNS Scanner.</p>');
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to send test email: ' + err.message }); }
});

// ─── Get SMTP config ───
router.get('/smtp', requireAdmin, async (req, res) => {
  try {
    const result = await query('SELECT id, smtp_host, smtp_port, smtp_user, smtp_secure, smtp_from FROM smtp_config LIMIT 1');
    res.json(result.rows[0] || {});
  } catch (err) { res.status(500).json({ error: 'Failed to fetch SMTP config' }); }
});

// ─── Update SMTP config ───
router.put('/smtp', requireAdmin, async (req, res) => {
  try {
    const { smtp_host, smtp_port, smtp_user, smtp_pass, smtp_secure, smtp_from } = req.body;
    if (!smtp_host) return res.status(400).json({ error: 'SMTP host is required' });
    const encryptedPass = smtp_pass ? encrypt(smtp_pass) : '';
    await query('DELETE FROM smtp_config');
    await query('INSERT INTO smtp_config (smtp_host, smtp_port, smtp_user, smtp_pass, smtp_secure, smtp_from) VALUES ($1, $2, $3, $4, $5, $6)',
      [smtp_host, smtp_port || 587, smtp_user || '', encryptedPass, smtp_secure !== false, smtp_from || '']);
    logAudit(req, 'smtp.update', 'smtp_config', null);
    console.log(`[SMTP] Config updated by admin ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update SMTP config' }); }
});

module.exports = router;
