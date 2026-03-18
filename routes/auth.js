'use strict';
const router = require('express').Router();
const bcrypt = require('bcrypt');
const crypto = require('node:crypto');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { getPool, query } = require('../db');
const { requireAuth, requireAdmin, validateId, logAudit } = require('../middleware');
const { USER_ROLES } = require('../constants');
const { getSetting } = require('../settings-service');

// ─── WebAuthn helpers ───
async function getWebAuthnConfig(req) {
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const host = req.get('x-forwarded-host') || req.get('host');
  const hostname = host.split(':')[0];
  return {
    rpID: (await getSetting('webauthn_rp_id')) || hostname,
    rpName: (await getSetting('webauthn_rp_name')) || 'DNS Scanner',
    origin: (await getSetting('webauthn_origin')) || `${proto}://${host}`,
  };
}

async function isGoogleAuthConfigured() {
  const clientId = await getSetting('google_client_id');
  const clientSecret = await getSetting('google_client_secret');
  return !!(clientId && clientSecret);
}

// ─── Register ───
router.post('/register', async (req, res) => {
  try {
    if ((await getSetting('registration_enabled')) === 'false') return res.status(403).json({ error: 'Registration is disabled' });
    const { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-30 alphanumeric characters or underscores' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });

    const existing = await query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'Username already taken' });

    const client = await getPool().connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1)');
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

      req.session.regenerate((err) => {
        if (err) return res.status(500).json({ error: 'Session error' });
        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.save((saveErr) => {
          if (saveErr) return res.status(500).json({ error: 'Session save error' });
          logAudit(req, 'user.register', 'user', user.id);
          console.log(`[AUTH] User registered: ${username} (${role})`);
          res.status(201).json({ id: user.id, username: user.username, role: user.role });
        });
      });
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

// ─── Login ───
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const result = await query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({ error: 'Account locked. Try again later.' });
    }

    if (!user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      const attempts = (user.failed_login_attempts || 0) + 1;
      const lockUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
      await query('UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3', [attempts, lockUntil, user.id]);
      console.log(`[AUTH] Failed login for ${username} (attempt ${attempts})`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);

    // Check if 2FA is required
    if (user.passkey_mode === 'twofactor') {
      const creds = await query('SELECT COUNT(*) as count FROM user_credentials WHERE user_id = $1', [user.id]);
      if (parseInt(creds.rows[0].count) > 0) {
        req.session.regenerate((err) => {
          if (err) return res.status(500).json({ error: 'Session error' });
          req.session.pending2faUserId = user.id;
          req.session.pending2faRole = user.role;
          req.session.save((saveErr) => {
            if (saveErr) return res.status(500).json({ error: 'Session save error' });
            res.json({ requires2fa: true });
          });
        });
        return;
      }
    }

    const userData = { id: user.id, username: user.username, role: user.role, email: user.email };
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Session save error' });
        logAudit(req, 'user.login', 'user', user.id);
        console.log(`[AUTH] Login: ${username}`);
        res.json(userData);
      });
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ─── Logout ───
router.post('/logout', (req, res) => {
  const userId = req.session?.userId;
  req.session.destroy(() => {
    if (userId) logAudit(req, 'user.logout', 'user', userId);
    res.json({ ok: true });
  });
});

// ─── Me ───
router.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT u.id, u.username, u.email, u.role, u.created_at, u.passkey_mode,
              (u.google_id IS NOT NULL) as google_linked,
              (u.password_hash IS NOT NULL) as has_password,
              (SELECT COUNT(*)::int FROM user_credentials WHERE user_id = u.id) as passkey_count
       FROM users u WHERE u.id = $1`,
      [req.session.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ─── Change password ───
router.put('/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: 'New password is required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const result = await query('SELECT password_hash FROM users WHERE id = $1', [req.session.userId]);
    const user = result.rows[0];
    if (user.password_hash) {
      if (!currentPassword) return res.status(400).json({ error: 'Current password is required' });
      const valid = await bcrypt.compare(currentPassword, user.password_hash);
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    }
    const hash = await bcrypt.hash(newPassword, 12);
    await query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.session.userId]);
    const currentSid = req.sessionID;
    await query("DELETE FROM session WHERE sid != $1 AND sess::text LIKE $2", [currentSid, `%"userId":${req.session.userId}%`]);
    logAudit(req, 'user.password_change', 'user', req.session.userId);
    console.log(`[AUTH] Password changed for user ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to change password' }); }
});

// ─── Forgot password ───
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const result = await query('SELECT id, username FROM users WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      await query('UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE', [user.id]);
      const token = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      await query(
        'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
        [user.id, tokenHash, expiresAt]
      );
      const proto = req.get('x-forwarded-proto') || req.protocol;
      const host = req.get('x-forwarded-host') || req.get('host');
      const resetUrl = `${proto}://${host}/#reset-password/${token}`;
      const html = `
        <h2>Password Reset</h2>
        <p>Hi ${user.username},</p>
        <p>A password reset was requested for your DNS Scanner account.</p>
        <p><a href="${resetUrl}" style="display:inline-block;padding:10px 24px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:6px;">Reset Password</a></p>
        <p>Or copy this link: ${resetUrl}</p>
        <p>This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
      `;
      try {
        const { sendEmail } = require('../notifier');
        await sendEmail(email, 'DNS Scanner - Password Reset', html);
        console.log(`[AUTH] Password reset email sent for user ${user.id}`);
      } catch (emailErr) {
        console.error('[AUTH] Failed to send reset email:', emailErr.message);
      }
    }
    res.json({ ok: true, message: 'If an account with that email exists, a reset link has been sent.' });
  } catch (err) {
    console.error('[AUTH] Forgot password error:', err.message);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// ─── Reset password ───
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const result = await query(
      'SELECT * FROM password_reset_tokens WHERE token_hash = $1 AND used = FALSE AND expires_at > NOW()',
      [tokenHash]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired reset link' });

    const resetToken = result.rows[0];
    const hash = await bcrypt.hash(newPassword, 12);
    await query('UPDATE users SET password_hash = $1, failed_login_attempts = 0, locked_until = NULL WHERE id = $2', [hash, resetToken.user_id]);
    await query('UPDATE password_reset_tokens SET used = TRUE WHERE id = $1', [resetToken.id]);
    await query("DELETE FROM session WHERE sess::text LIKE $1", [`%"userId":${resetToken.user_id}%`]);
    logAudit(req, 'user.password_reset', 'user', resetToken.user_id);
    console.log(`[AUTH] Password reset completed for user ${resetToken.user_id}`);
    res.json({ ok: true });
  } catch (err) {
    console.error('[AUTH] Reset password error:', err.message);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ─── Passkey registration options ───
router.post('/passkey/register-options', requireAuth, async (req, res) => {
  try {
    const { rpID, rpName } = await getWebAuthnConfig(req);
    const userResult = await query('SELECT id, username FROM users WHERE id = $1', [req.session.userId]);
    const user = userResult.rows[0];
    const existing = await query('SELECT credential_id FROM user_credentials WHERE user_id = $1', [user.id]);
    const excludeCredentials = existing.rows.map(c => ({ id: c.credential_id, transports: ['internal', 'hybrid'] }));

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: user.username,
      userID: new TextEncoder().encode(String(user.id)),
      excludeCredentials,
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      attestationType: 'none',
    });

    await query('DELETE FROM webauthn_challenges WHERE session_id = $1', [req.sessionID]);
    await query(
      'INSERT INTO webauthn_challenges (session_id, challenge, user_id, type, expires_at) VALUES ($1, $2, $3, $4, $5)',
      [req.sessionID, options.challenge, user.id, 'registration', new Date(Date.now() + 5 * 60 * 1000)]
    );
    res.json(options);
  } catch (err) {
    console.error('[PASSKEY] Register options error:', err.message);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

// ─── Passkey registration verify ───
router.post('/passkey/register-verify', requireAuth, async (req, res) => {
  try {
    const { rpID, origin } = await getWebAuthnConfig(req);
    const challengeResult = await query(
      'SELECT challenge FROM webauthn_challenges WHERE session_id = $1 AND type = $2 AND expires_at > NOW()',
      [req.sessionID, 'registration']
    );
    if (challengeResult.rows.length === 0) return res.status(400).json({ error: 'Challenge expired, please try again' });

    const verification = await verifyRegistrationResponse({
      response: req.body.credential,
      expectedChallenge: challengeResult.rows[0].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Verification failed' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    await query(
      `INSERT INTO user_credentials (user_id, credential_id, public_key, counter, device_type, backed_up, transports, name)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        req.session.userId,
        credential.id,
        Buffer.from(credential.publicKey).toString('base64url'),
        credential.counter,
        credentialDeviceType,
        credentialBackedUp,
        JSON.stringify(credential.transports || []),
        req.body.name || 'Passkey',
      ]
    );
    await query('DELETE FROM webauthn_challenges WHERE session_id = $1', [req.sessionID]);
    console.log(`[PASSKEY] Registered passkey for user ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) {
    console.error('[PASSKEY] Register verify error:', err.message);
    res.status(500).json({ error: 'Failed to verify registration' });
  }
});

// ─── Passkey login options ───
router.post('/passkey/login-options', async (req, res) => {
  try {
    const { rpID } = await getWebAuthnConfig(req);
    const { username } = req.body || {};
    let allowCredentials;

    if (username) {
      const userResult = await query('SELECT id FROM users WHERE username = $1', [username]);
      if (userResult.rows.length > 0) {
        const creds = await query('SELECT credential_id, transports FROM user_credentials WHERE user_id = $1', [userResult.rows[0].id]);
        allowCredentials = creds.rows.map(c => ({ id: c.credential_id, transports: c.transports || ['internal', 'hybrid'] }));
      }
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
    });

    await query('DELETE FROM webauthn_challenges WHERE session_id = $1', [req.sessionID]);
    await query(
      'INSERT INTO webauthn_challenges (session_id, challenge, type, expires_at) VALUES ($1, $2, $3, $4)',
      [req.sessionID, options.challenge, 'authentication', new Date(Date.now() + 5 * 60 * 1000)]
    );
    res.json(options);
  } catch (err) {
    console.error('[PASSKEY] Login options error:', err.message);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

// ─── Passkey login verify ───
router.post('/passkey/login-verify', async (req, res) => {
  try {
    const { rpID, origin } = await getWebAuthnConfig(req);
    const challengeResult = await query(
      'SELECT challenge FROM webauthn_challenges WHERE session_id = $1 AND type = $2 AND expires_at > NOW()',
      [req.sessionID, 'authentication']
    );
    if (challengeResult.rows.length === 0) return res.status(400).json({ error: 'Challenge expired, please try again' });

    const credResult = await query('SELECT * FROM user_credentials WHERE credential_id = $1', [req.body.credential.id]);
    if (credResult.rows.length === 0) return res.status(401).json({ error: 'Passkey not recognized' });
    const storedCred = credResult.rows[0];

    const verification = await verifyAuthenticationResponse({
      response: req.body.credential,
      expectedChallenge: challengeResult.rows[0].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: storedCred.credential_id,
        publicKey: Buffer.from(storedCred.public_key, 'base64url'),
        counter: parseInt(storedCred.counter),
        transports: storedCred.transports || [],
      },
    });

    if (!verification.verified) return res.status(401).json({ error: 'Passkey verification failed' });

    await query('UPDATE user_credentials SET counter = $1, last_used_at = NOW() WHERE id = $2',
      [verification.authenticationInfo.newCounter, storedCred.id]);
    await query('DELETE FROM webauthn_challenges WHERE session_id = $1', [req.sessionID]);

    const userResult = await query('SELECT * FROM users WHERE id = $1', [storedCred.user_id]);
    const user = userResult.rows[0];
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({ error: 'Account locked. Try again later.' });
    }
    if (user.passkey_mode === 'twofactor') {
      return res.status(400).json({ error: 'This account requires password + passkey. Please use password login first.' });
    }

    await query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);
    const userData = { id: user.id, username: user.username, role: user.role, email: user.email };
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Session save error' });
        logAudit(req, 'user.login', 'user', user.id);
        console.log(`[AUTH] Passkey login: ${user.username}`);
        res.json(userData);
      });
    });
  } catch (err) {
    console.error('[PASSKEY] Login verify error:', err.message);
    res.status(500).json({ error: 'Passkey login failed' });
  }
});

// ─── Passkey 2FA options ───
router.post('/passkey/2fa-options', async (req, res) => {
  try {
    if (!req.session.pending2faUserId) return res.status(400).json({ error: 'No pending 2FA verification' });
    const { rpID } = await getWebAuthnConfig(req);

    const creds = await query('SELECT credential_id, transports FROM user_credentials WHERE user_id = $1', [req.session.pending2faUserId]);
    const allowCredentials = creds.rows.map(c => ({ id: c.credential_id, transports: c.transports || ['internal', 'hybrid'] }));

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
    });

    await query('DELETE FROM webauthn_challenges WHERE session_id = $1', [req.sessionID]);
    await query(
      'INSERT INTO webauthn_challenges (session_id, challenge, user_id, type, expires_at) VALUES ($1, $2, $3, $4, $5)',
      [req.sessionID, options.challenge, req.session.pending2faUserId, 'authentication', new Date(Date.now() + 5 * 60 * 1000)]
    );
    res.json(options);
  } catch (err) {
    console.error('[PASSKEY] 2FA options error:', err.message);
    res.status(500).json({ error: 'Failed to generate 2FA options' });
  }
});

// ─── Passkey 2FA verify ───
router.post('/passkey/verify-2fa', async (req, res) => {
  try {
    if (!req.session.pending2faUserId) return res.status(400).json({ error: 'No pending 2FA verification' });
    const { rpID, origin } = await getWebAuthnConfig(req);

    const challengeResult = await query(
      'SELECT challenge FROM webauthn_challenges WHERE session_id = $1 AND type = $2 AND expires_at > NOW()',
      [req.sessionID, 'authentication']
    );
    if (challengeResult.rows.length === 0) return res.status(400).json({ error: 'Challenge expired, please try again' });

    const credResult = await query('SELECT * FROM user_credentials WHERE credential_id = $1 AND user_id = $2',
      [req.body.credential.id, req.session.pending2faUserId]);
    if (credResult.rows.length === 0) return res.status(401).json({ error: 'Passkey not recognized for this account' });
    const storedCred = credResult.rows[0];

    const verification = await verifyAuthenticationResponse({
      response: req.body.credential,
      expectedChallenge: challengeResult.rows[0].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: storedCred.credential_id,
        publicKey: Buffer.from(storedCred.public_key, 'base64url'),
        counter: parseInt(storedCred.counter),
        transports: storedCred.transports || [],
      },
    });

    if (!verification.verified) return res.status(401).json({ error: 'Passkey verification failed' });

    await query('UPDATE user_credentials SET counter = $1, last_used_at = NOW() WHERE id = $2',
      [verification.authenticationInfo.newCounter, storedCred.id]);
    await query('DELETE FROM webauthn_challenges WHERE session_id = $1', [req.sessionID]);

    const userId = req.session.pending2faUserId;
    const role = req.session.pending2faRole;
    const userResult = await query('SELECT username, email FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];

    delete req.session.pending2faUserId;
    delete req.session.pending2faRole;
    req.session.userId = userId;
    req.session.role = role;
    req.session.save((saveErr) => {
      if (saveErr) return res.status(500).json({ error: 'Session save error' });
      logAudit(req, 'user.login', 'user', userId);
      console.log(`[AUTH] 2FA login: ${user.username}`);
      res.json({ id: userId, username: user.username, role, email: user.email });
    });
  } catch (err) {
    console.error('[PASSKEY] 2FA verify error:', err.message);
    res.status(500).json({ error: '2FA verification failed' });
  }
});

// ─── Passkey credentials list ───
router.get('/passkey/credentials', requireAuth, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, name, device_type, backed_up, created_at, last_used_at FROM user_credentials WHERE user_id = $1 ORDER BY created_at',
      [req.session.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch passkeys' }); }
});

// ─── Delete passkey ───
router.delete('/passkey/credentials/:id', requireAuth, validateId, async (req, res) => {
  try {
    const cred = await query('SELECT id FROM user_credentials WHERE id = $1 AND user_id = $2', [req.params.id, req.session.userId]);
    if (cred.rows.length === 0) return res.status(404).json({ error: 'Passkey not found' });

    const user = await query('SELECT password_hash, passkey_mode FROM users WHERE id = $1', [req.session.userId]);
    const credCount = await query('SELECT COUNT(*) as count FROM user_credentials WHERE user_id = $1', [req.session.userId]);
    if (parseInt(credCount.rows[0].count) <= 1 && !user.rows[0].password_hash) {
      return res.status(400).json({ error: 'Cannot delete last passkey without a password set' });
    }

    await query('DELETE FROM user_credentials WHERE id = $1', [req.params.id]);
    const remaining = await query('SELECT COUNT(*) as count FROM user_credentials WHERE user_id = $1', [req.session.userId]);
    if (parseInt(remaining.rows[0].count) === 0) {
      await query("UPDATE users SET passkey_mode = 'either' WHERE id = $1", [req.session.userId]);
    }
    console.log(`[PASSKEY] Deleted passkey ${req.params.id} for user ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete passkey' }); }
});

// ─── Passkey mode ───
router.put('/passkey/mode', requireAuth, async (req, res) => {
  try {
    const { mode } = req.body;
    if (!['passwordless', 'twofactor', 'either'].includes(mode)) {
      return res.status(400).json({ error: 'Invalid mode. Must be: passwordless, twofactor, or either' });
    }
    const credCount = await query('SELECT COUNT(*) as count FROM user_credentials WHERE user_id = $1', [req.session.userId]);
    if (parseInt(credCount.rows[0].count) === 0 && mode !== 'either') {
      return res.status(400).json({ error: 'Register a passkey first before changing mode' });
    }
    if (mode === 'twofactor') {
      const user = await query('SELECT password_hash FROM users WHERE id = $1', [req.session.userId]);
      if (!user.rows[0].password_hash) {
        return res.status(400).json({ error: 'Two-factor mode requires a password. Set a password first.' });
      }
    }
    await query('UPDATE users SET passkey_mode = $1 WHERE id = $2', [mode, req.session.userId]);
    res.json({ ok: true, mode });
  } catch (err) { res.status(500).json({ error: 'Failed to update passkey mode' }); }
});

// ─── Google OAuth status ───
router.get('/google/status', async (req, res) => {
  if (!(await isGoogleAuthConfigured())) return res.json({ enabled: false });
  try {
    const enabled = (await getSetting('google_auth_enabled')) !== 'false';
    const clientId = await getSetting('google_client_id');
    res.json({ enabled, clientId });
  } catch (err) { res.json({ enabled: false }); }
});

// ─── Google OAuth start ───
router.get('/google', (req, res) => {
  if (!isGoogleAuthConfigured()) return res.status(404).json({ error: 'Google auth not configured' });
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const host = req.get('x-forwarded-host') || req.get('host');
  const redirectUri = `${proto}://${host}/api/auth/google/callback`;
  const state = crypto.randomBytes(32).toString('hex');
  req.session.googleOAuthState = state;
  req.session.save(() => {
    const params = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      access_type: 'online',
      prompt: 'select_account',
    });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  });
});

// ─── Google OAuth callback ───
router.get('/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || state !== req.session.googleOAuthState) {
      return res.redirect('/#login?error=google_auth_failed');
    }
    delete req.session.googleOAuthState;

    const proto = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('x-forwarded-host') || req.get('host');
    const redirectUri = `${proto}://${host}/api/auth/google/callback`;

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });
    if (!tokenRes.ok) return res.redirect('/#login?error=google_token_failed');
    const tokens = await tokenRes.json();

    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!userInfoRes.ok) return res.redirect('/#login?error=google_userinfo_failed');
    const googleUser = await userInfoRes.json();

    // If user is already logged in, link Google account
    if (req.session.userId) {
      await query('UPDATE users SET google_id = $1 WHERE id = $2', [googleUser.id, req.session.userId]);
      console.log(`[AUTH] Linked Google account for user ${req.session.userId}`);
      return res.redirect('/#settings');
    }

    // Check if google_id matches existing user
    let userResult = await query('SELECT * FROM users WHERE google_id = $1', [googleUser.id]);
    if (userResult.rows.length > 0) {
      const user = userResult.rows[0];
      req.session.regenerate((err) => {
        if (err) return res.redirect('/#login?error=session_error');
        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.save(() => {
          console.log(`[AUTH] Google login: ${user.username}`);
          res.redirect('/#dashboard');
        });
      });
      return;
    }

    // Check if email matches existing user
    if (googleUser.email) {
      userResult = await query('SELECT * FROM users WHERE email = $1', [googleUser.email]);
      if (userResult.rows.length > 0) {
        const user = userResult.rows[0];
        await query('UPDATE users SET google_id = $1 WHERE id = $2', [googleUser.id, user.id]);
        req.session.regenerate((err) => {
          if (err) return res.redirect('/#login?error=session_error');
          req.session.userId = user.id;
          req.session.role = user.role;
          req.session.save(() => {
            console.log(`[AUTH] Google login (email linked): ${user.username}`);
            res.redirect('/#dashboard');
          });
        });
        return;
      }
    }

    // First user must register with password
    const userCount = await query('SELECT COUNT(*) as count FROM users');
    if (parseInt(userCount.rows[0].count) === 0) {
      return res.redirect('/#register?error=first_user_must_register');
    }

    // Create new account
    const baseUsername = (googleUser.name || googleUser.email.split('@')[0]).replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 25);
    let username = baseUsername;
    let suffix = 1;
    while (true) {
      const existing = await query('SELECT id FROM users WHERE username = $1', [username]);
      if (existing.rows.length === 0) break;
      username = `${baseUsername}_${suffix++}`;
      if (username.length > 30) username = username.substring(0, 30);
    }

    const client = await getPool().connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        'INSERT INTO users (username, email, google_id, role) VALUES ($1, $2, $3, $4) RETURNING id, username, role, email',
        [username, googleUser.email || null, googleUser.id, USER_ROLES.VIEWER]
      );
      const newUser = result.rows[0];
      await client.query('INSERT INTO notification_settings (user_id) VALUES ($1)', [newUser.id]);
      await client.query('COMMIT');

      req.session.regenerate((err) => {
        if (err) return res.redirect('/#login?error=session_error');
        req.session.userId = newUser.id;
        req.session.role = newUser.role;
        req.session.save(() => {
          console.log(`[AUTH] Google signup: ${newUser.username}`);
          res.redirect('/#dashboard');
        });
      });
    } catch (innerErr) {
      await client.query('ROLLBACK');
      throw innerErr;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('[AUTH] Google callback error:', err.message);
    res.redirect('/#login?error=google_auth_failed');
  }
});

// ─── Unlink Google ───
router.delete('/google/link', requireAuth, async (req, res) => {
  try {
    const user = await query('SELECT password_hash FROM users WHERE id = $1', [req.session.userId]);
    const credCount = await query('SELECT COUNT(*) as count FROM user_credentials WHERE user_id = $1', [req.session.userId]);
    if (!user.rows[0].password_hash && parseInt(credCount.rows[0].count) === 0) {
      return res.status(400).json({ error: 'Cannot unlink Google without another authentication method (password or passkey)' });
    }
    await query('UPDATE users SET google_id = NULL WHERE id = $1', [req.session.userId]);
    console.log(`[AUTH] Unlinked Google for user ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to unlink Google' }); }
});

// ─── Invite validation ───
router.get('/invite/:token', async (req, res) => {
  try {
    const { token } = req.params;
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return res.status(400).json({ error: 'Invalid invite link' });
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const result = await query(
      'SELECT email, role FROM user_invites WHERE token_hash = $1 AND accepted = FALSE AND expires_at > NOW()',
      [tokenHash]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Invalid or expired invitation' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to validate invite' }); }
});

// ─── Accept invite ───
router.post('/accept-invite', async (req, res) => {
  try {
    const { token, username, password } = req.body;
    if (!token || !username || !password) return res.status(400).json({ error: 'Token, username, and password are required' });
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-30 alphanumeric characters or underscores' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const invite = await query(
      'SELECT * FROM user_invites WHERE token_hash = $1 AND accepted = FALSE AND expires_at > NOW()',
      [tokenHash]
    );
    if (invite.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired invitation' });

    const inv = invite.rows[0];
    const existing = await query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'Username already taken' });

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await query(
      'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, role',
      [username, inv.email, passwordHash, inv.role]
    );
    const user = result.rows[0];
    await query('INSERT INTO notification_settings (user_id) VALUES ($1)', [user.id]);
    await query('UPDATE user_invites SET accepted = TRUE WHERE id = $1', [inv.id]);

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Session save error' });
        logAudit(req, 'user.register', 'user', user.id);
        console.log(`[AUTH] User registered via invite: ${username} (${user.role})`);
        res.status(201).json({ id: user.id, username: user.username, role: user.role });
      });
    });
  } catch (err) {
    console.error('[AUTH] Accept invite error:', err.message);
    res.status(500).json({ error: 'Failed to accept invitation' });
  }
});

// ─── API Keys ───
router.post('/api-keys', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || name.length > 100) return res.status(400).json({ error: 'API key name is required (max 100 chars)' });

    const rawKey = 'dnss_' + crypto.randomBytes(32).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const keyPrefix = rawKey.substring(0, 13); // 'dnss_' + first 8 hex chars

    const result = await query(
      'INSERT INTO api_keys (user_id, name, key_hash, key_prefix) VALUES ($1, $2, $3, $4) RETURNING id, name, key_prefix, created_at',
      [req.session.userId, name, keyHash, keyPrefix]
    );

    res.status(201).json({ ...result.rows[0], key: rawKey });
  } catch (err) {
    console.error('[AUTH] API key creation error:', err.message);
    res.status(500).json({ error: 'Failed to create API key' });
  }
});

router.get('/api-keys', requireAuth, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, name, key_prefix, last_used_at, created_at FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC',
      [req.session.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch API keys' }); }
});

router.delete('/api-keys/:id', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('DELETE FROM api_keys WHERE id = $1 AND user_id = $2 RETURNING id', [req.params.id, req.session.userId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'API key not found' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete API key' }); }
});

module.exports = router;
