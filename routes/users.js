'use strict';
const router = require('express').Router();
const crypto = require('node:crypto');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { query } = require('../db');
const { requireAdmin, validateId, logAudit } = require('../middleware');
const { USER_ROLES } = require('../constants');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });

// ─── List all users ───
router.get('/', requireAdmin, async (req, res) => {
  try {
    const result = await query('SELECT id, username, email, role, allowed_tags, created_at FROM users ORDER BY created_at');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch users' }); }
});

// ─── Update user ───
router.put('/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const { role, email, allowed_tags } = req.body;
    if (parseInt(req.params.id) === req.session.userId && role && role !== req.session.role) {
      return res.status(400).json({ error: 'Cannot change your own role' });
    }
    if (role && !Object.values(USER_ROLES).includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const updates = [];
    const params = [];
    let i = 1;
    if (role) { updates.push(`role = $${i++}`); params.push(role); }
    if (email !== undefined) { updates.push(`email = $${i++}`); params.push(email || null); }
    if (allowed_tags !== undefined) { updates.push(`allowed_tags = $${i++}`); params.push(allowed_tags ? JSON.stringify(allowed_tags) : null); }
    if (updates.length === 0) return res.status(400).json({ error: 'Nothing to update' });
    params.push(req.params.id);
    await query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${i}`, params);
    logAudit(req, 'user.update', 'user', req.params.id);
    console.log(`[AUTH] User ${req.params.id} updated by admin ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update user' }); }
});

// ─── Delete user ───
router.delete('/:id', requireAdmin, validateId, async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
    await query('DELETE FROM users WHERE id = $1', [req.params.id]);
    logAudit(req, 'user.delete', 'user', req.params.id);
    console.log(`[AUTH] User ${req.params.id} deleted by admin ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete user' }); }
});

// ─── Invite user ───
router.post('/invite', requireAdmin, async (req, res) => {
  try {
    const { email, role } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Valid email is required' });
    const inviteRole = role && Object.values(USER_ROLES).includes(role) ? role : USER_ROLES.VIEWER;

    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'A user with this email already exists' });

    await query('UPDATE user_invites SET accepted = TRUE WHERE email = $1 AND accepted = FALSE', [email]);

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await query(
      'INSERT INTO user_invites (email, role, token_hash, invited_by, expires_at) VALUES ($1, $2, $3, $4, $5)',
      [email, inviteRole, tokenHash, req.session.userId, expiresAt]
    );

    const proto = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('x-forwarded-host') || req.get('host');
    const inviteUrl = `${proto}://${host}/#accept-invite/${token}`;
    const html = `
      <h2>You're Invited to DNS Scanner</h2>
      <p>You've been invited to join DNS Scanner as a <strong>${inviteRole}</strong>.</p>
      <p><a href="${inviteUrl}" style="display:inline-block;padding:10px 24px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:6px;">Accept Invitation</a></p>
      <p>Or copy this link: ${inviteUrl}</p>
      <p>This invitation expires in 7 days.</p>
    `;
    try {
      const { sendEmail } = require('../notifier');
      await sendEmail(email, 'DNS Scanner - You\'re Invited', html);
      logAudit(req, 'user.invite', 'user_invite', null, { email, role: inviteRole });
      console.log(`[AUTH] Invite email sent to ${email} by admin ${req.session.userId}`);
    } catch (emailErr) {
      console.error('[AUTH] Failed to send invite email:', emailErr.message);
      logAudit(req, 'user.invite', 'user_invite', null, { email, role: inviteRole });
      return res.status(201).json({ ok: true, inviteUrl, warning: 'Invite created but email could not be sent. Share the link manually.' });
    }

    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('[AUTH] Invite error:', err.message);
    res.status(500).json({ error: 'Failed to create invite' });
  }
});

// ─── List pending invites ───
router.get('/invites', requireAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT ui.id, ui.email, ui.role, ui.accepted, ui.expires_at, ui.created_at,
             u.username as invited_by_username
      FROM user_invites ui
      LEFT JOIN users u ON u.id = ui.invited_by
      WHERE ui.accepted = FALSE AND ui.expires_at > NOW()
      ORDER BY ui.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch invites' }); }
});

// ─── Revoke invite ───
router.delete('/invites/:id', requireAdmin, validateId, async (req, res) => {
  try {
    await query('DELETE FROM user_invites WHERE id = $1', [req.params.id]);
    logAudit(req, 'user.invite_revoke', 'user_invite', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to revoke invite' }); }
});

// ─── Export users as CSV ───
router.get('/export', requireAdmin, async (req, res) => {
  try {
    const result = await query('SELECT username, email, role FROM users ORDER BY created_at');
    let csv = 'username,email,role\n';
    for (const row of result.rows) {
      csv += `${row.username},${row.email || ''},${row.role}\n`;
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="users-export.csv"');
    res.send(csv);
  } catch (err) { res.status(500).json({ error: 'Failed to export users' }); }
});

// ─── Import users from CSV ───
router.post('/import', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'CSV file required' });
    const csv = req.file.buffer.toString('utf8');
    const lines = csv.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('email,') && !l.startsWith('username,'));

    const results = { invited: 0, skipped: 0, errors: [] };
    for (const line of lines) {
      const parts = line.split(',').map(p => p.trim());
      const email = parts[0];
      const role = parts[1] && Object.values(USER_ROLES).includes(parts[1]) ? parts[1] : USER_ROLES.VIEWER;

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        results.errors.push(`Invalid email: ${parts[0]}`);
        results.skipped++;
        continue;
      }

      try {
        const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
        if (existing.rows.length > 0) {
          results.errors.push(`Already exists: ${email}`);
          results.skipped++;
          continue;
        }

        await query('UPDATE user_invites SET accepted = TRUE WHERE email = $1 AND accepted = FALSE', [email]);

        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        await query(
          'INSERT INTO user_invites (email, role, token_hash, invited_by, expires_at) VALUES ($1, $2, $3, $4, $5)',
          [email, role, tokenHash, req.session.userId, expiresAt]
        );

        const proto = req.get('x-forwarded-proto') || req.protocol;
        const host = req.get('x-forwarded-host') || req.get('host');
        const inviteUrl = `${proto}://${host}/#accept-invite/${token}`;
        const html = `
          <h2>You're Invited to DNS Scanner</h2>
          <p>You've been invited to join DNS Scanner as a <strong>${role}</strong>.</p>
          <p><a href="${inviteUrl}" style="display:inline-block;padding:10px 24px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:6px;">Accept Invitation</a></p>
          <p>Or copy this link: ${inviteUrl}</p>
          <p>This invitation expires in 7 days.</p>
        `;
        try {
          const { sendEmail } = require('../notifier');
          await sendEmail(email, 'DNS Scanner - You\'re Invited', html);
        } catch (emailErr) {
          console.error(`[AUTH] Failed to send invite email to ${email}:`, emailErr.message);
        }
        results.invited++;
      } catch (err) {
        results.errors.push(`Error: ${email} - ${err.message}`);
        results.skipped++;
      }
    }
    console.log(`[AUTH] Bulk import: ${results.invited} invited, ${results.skipped} skipped`);
    res.json(results);
  } catch (err) { res.status(500).json({ error: 'Import failed' }); }
});

module.exports = router;
