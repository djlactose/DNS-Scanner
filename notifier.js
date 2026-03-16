'use strict';

const webpush = require('web-push');
const nodemailer = require('nodemailer');
const crypto = require('node:crypto');
const { query } = require('./db');
const { decrypt } = require('./crypto-utils');
const { HEALTH_STATUS, CONSECUTIVE_FAILURES_THRESHOLD, EXPIRY_WARNING_DAYS, WEBHOOK_EVENT_TYPES } = require('./constants');

async function getVapidKeys() {
  const pubResult = await query("SELECT value FROM app_settings WHERE key = 'vapid_public_key'");
  const privResult = await query("SELECT value FROM app_settings WHERE key = 'vapid_private_key'");

  if (pubResult.rows.length > 0 && privResult.rows.length > 0) {
    return { publicKey: pubResult.rows[0].value, privateKey: privResult.rows[0].value };
  }

  const keys = webpush.generateVAPIDKeys();
  await query("INSERT INTO app_settings (key, value) VALUES ('vapid_public_key', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [keys.publicKey]);
  await query("INSERT INTO app_settings (key, value) VALUES ('vapid_private_key', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [keys.privateKey]);
  console.log('[NOTIFIER] Generated new VAPID keys');
  return keys;
}

async function getVapidPublicKey() {
  const keys = await getVapidKeys();
  return keys.publicKey;
}

async function sendPushToUser(userId, payload) {
  const keys = await getVapidKeys();
  webpush.setVapidDetails('mailto:admin@dns-scanner.local', keys.publicKey, keys.privateKey);

  const subs = await query('SELECT * FROM push_subscriptions WHERE user_id = $1', [userId]);
  for (const sub of subs.rows) {
    try {
      await webpush.sendNotification(
        { endpoint: sub.endpoint, keys: { p256dh: sub.keys_p256dh, auth: sub.keys_auth } },
        JSON.stringify(payload)
      );
    } catch (err) {
      if (err.statusCode === 404 || err.statusCode === 410) {
        await query('DELETE FROM push_subscriptions WHERE id = $1', [sub.id]);
      }
      console.error(`[PUSH] Error sending to user ${userId}:`, err.message);
    }
  }
}

async function getSmtpTransport() {
  const config = await query('SELECT * FROM smtp_config LIMIT 1');
  if (config.rows.length === 0) return null;
  const c = config.rows[0];
  const transportOpts = {
    host: c.smtp_host,
    port: c.smtp_port,
    secure: c.smtp_secure,
  };
  if (c.smtp_pass) {
    transportOpts.auth = { user: c.smtp_user, pass: decrypt(c.smtp_pass) };
  }
  return nodemailer.createTransport(transportOpts);
}

async function sendEmail(to, subject, html) {
  const transport = await getSmtpTransport();
  if (!transport) throw new Error('SMTP not configured');
  await transport.sendMail({ from: '"DNS Scanner" <noreply@dns-scanner.local>', to, subject, html });
}

async function deliverWebhook(webhook, eventType, data) {
  const payload = { event: eventType, timestamp: new Date().toISOString(), ...data };
  const body = JSON.stringify(payload);
  const signature = webhook.secret ? crypto.createHmac('sha256', webhook.secret).update(body).digest('hex') : '';

  const delays = [0, 1000, 5000, 30000];
  let lastError = null;
  let responseStatus = null;
  let responseBody = null;

  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, delays[attempt]));
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      const resp = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Signature-256': `sha256=${signature}`,
          'User-Agent': 'DNS-Scanner-Webhook/1.0',
        },
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);
      responseStatus = resp.status;
      responseBody = (await resp.text()).substring(0, 1024);

      if (resp.ok) {
        await query(
          'INSERT INTO webhook_deliveries (webhook_id, event_type, payload, response_status, response_body, attempts) VALUES ($1, $2, $3, $4, $5, $6)',
          [webhook.id, eventType, payload, responseStatus, responseBody, attempt + 1]
        );
        return;
      }
      lastError = `HTTP ${resp.status}`;
    } catch (err) {
      lastError = err.message;
    }
  }

  // Log failed delivery
  await query(
    'INSERT INTO webhook_deliveries (webhook_id, event_type, payload, response_status, response_body, attempts) VALUES ($1, $2, $3, $4, $5, $6)',
    [webhook.id, eventType, payload, responseStatus, lastError, 3]
  );
}

async function processPostScanNotifications(domain, scanId) {
  // Get scan results
  const deadRecords = await query(`
    SELECT dr.*, hc.status, hc.error_message
    FROM dns_records dr
    JOIN LATERAL (SELECT * FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) hc ON TRUE
    WHERE dr.domain_id = $1 AND dr.removed_at IS NULL AND dr.dismissed = FALSE
      AND hc.status IN ($2, $3)
  `, [domain.id, HEALTH_STATUS.DEAD, HEALTH_STATUS.TAKEOVER_RISK]);

  // Get recovered records (was dead, now alive)
  const recoveredRecords = await query(`
    SELECT dr.* FROM dns_records dr
    WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
      AND (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) = $2
      AND (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1 OFFSET 1) = $3
  `, [domain.id, HEALTH_STATUS.ALIVE, HEALTH_STATUS.DEAD]);

  // Get DNS changes
  const changes = await query(
    'SELECT * FROM dns_changes WHERE domain_id = $1 AND changed_at > NOW() - INTERVAL \'1 hour\'',
    [domain.id]
  );

  // Get all users with notification settings
  const users = await query(`
    SELECT u.id, u.email, ns.*
    FROM users u
    JOIN notification_settings ns ON ns.user_id = u.id
  `);

  // Get webhooks
  const webhooks = await query('SELECT * FROM webhooks WHERE enabled = TRUE');

  // Process notifications for each user
  for (const user of users.rows) {
    // Check tag filter
    if (user.notify_tags_only) {
      let tagIds;
      try { tagIds = typeof user.notify_tags_only === 'string' ? JSON.parse(user.notify_tags_only) : (user.notify_tags_only || []); } catch (e) { tagIds = []; }
      if (tagIds.length > 0) {
        const domainTags = await query('SELECT tag_id FROM domain_tags WHERE domain_id = $1', [domain.id]);
        const domainTagIds = domainTags.rows.map(r => r.tag_id);
        if (!tagIds.some(t => domainTagIds.includes(t))) continue;
      }
    }

    const notifications = [];

    // Dead records
    if (user.notify_on_dead && deadRecords.rows.length > 0) {
      for (const record of deadRecords.rows) {
        if (record.status === HEALTH_STATUS.DEAD) {
          // Check consecutive failures
          const failCount = await query(
            'SELECT COUNT(*) as count FROM (SELECT status FROM health_checks WHERE record_id = $1 ORDER BY checked_at DESC LIMIT $2) sub WHERE sub.status = $3',
            [record.id, CONSECUTIVE_FAILURES_THRESHOLD, HEALTH_STATUS.DEAD]
          );
          if (parseInt(failCount.rows[0].count) >= CONSECUTIVE_FAILURES_THRESHOLD) {
            notifications.push({ type: 'record.dead', title: `Dead: ${record.name}.${domain.domain}`, body: `${record.record_type} record ${record.name} (${record.value}) is dead. ${record.error_message || ''}`, record });
          }
        }
      }
    }

    // Takeover risk (immediate, no threshold)
    if (user.notify_on_takeover_risk) {
      for (const record of deadRecords.rows) {
        if (record.status === HEALTH_STATUS.TAKEOVER_RISK) {
          notifications.push({ type: 'record.takeover_risk', title: `TAKEOVER RISK: ${record.name}.${domain.domain}`, body: `CNAME ${record.name} -> ${record.value} may be vulnerable to subdomain takeover!`, record });
        }
      }
    }

    // Recovered records
    if (user.notify_on_recovery && recoveredRecords.rows.length > 0) {
      for (const record of recoveredRecords.rows) {
        notifications.push({ type: 'record.recovered', title: `Recovered: ${record.name}.${domain.domain}`, body: `${record.record_type} record ${record.name} is back online.`, record });
      }
    }

    // DNS changes
    if (user.notify_on_dns_change && changes.rows.length > 0) {
      for (const change of changes.rows) {
        notifications.push({ type: 'dns.changed', title: `DNS Changed: ${change.name}.${domain.domain}`, body: `${change.record_type} changed from ${change.old_value} to ${change.new_value}`, change });
      }
    }

    // Send push notifications
    if (user.push_enabled && notifications.length > 0) {
      for (const n of notifications) {
        await sendPushToUser(user.id, { title: n.title, body: n.body, data: { type: n.type, domainId: domain.id } });
      }
    }

    // Send email digest
    if (user.email_enabled && user.email && notifications.length > 0) {
      let html = `<h2>DNS Scanner Alert: ${domain.domain}</h2>`;
      for (const n of notifications) {
        const color = n.type.includes('dead') ? '#ef4444' : n.type.includes('takeover') ? '#7c3aed' : n.type.includes('recovered') ? '#22c55e' : '#3b82f6';
        html += `<div style="border-left:4px solid ${color};padding:8px 12px;margin:8px 0"><strong>${n.title}</strong><br>${n.body}</div>`;
      }
      try { await sendEmail(user.email, `DNS Scanner: ${notifications.length} alert(s) for ${domain.domain}`, html); } catch (e) { console.error(`[NOTIFIER] Email error for user ${user.id}:`, e.message); }
    }
  }

  // Send webhooks
  for (const webhook of webhooks.rows) {
    let events;
    try { events = typeof webhook.events === 'string' ? JSON.parse(webhook.events) : (webhook.events || []); } catch (e) { events = []; }

    // Scan completed event
    if (events.includes('scan.completed')) {
      await deliverWebhook(webhook, 'scan.completed', { domain: domain.domain, scanId, dead: deadRecords.rows.length });
    }

    for (const record of deadRecords.rows) {
      if (record.status === HEALTH_STATUS.DEAD && events.includes('record.dead')) {
        await deliverWebhook(webhook, 'record.dead', { domain: domain.domain, record: { type: record.record_type, name: record.name, value: record.value } });
      }
      if (record.status === HEALTH_STATUS.TAKEOVER_RISK && events.includes('record.takeover_risk')) {
        await deliverWebhook(webhook, 'record.takeover_risk', { domain: domain.domain, record: { type: record.record_type, name: record.name, value: record.value } });
      }
    }

    for (const record of recoveredRecords.rows) {
      if (events.includes('record.recovered')) {
        await deliverWebhook(webhook, 'record.recovered', { domain: domain.domain, record: { type: record.record_type, name: record.name, value: record.value } });
      }
    }

    for (const change of changes.rows) {
      if (events.includes('dns.changed')) {
        await deliverWebhook(webhook, 'dns.changed', { domain: domain.domain, record: { type: change.record_type, name: change.name }, old_value: change.old_value, new_value: change.new_value });
      }
    }
  }
}

module.exports = { getVapidPublicKey, sendPushToUser, sendEmail, deliverWebhook, processPostScanNotifications };
