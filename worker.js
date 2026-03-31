'use strict';

const { query, initSchema } = require('./db');
const { performScan, checkIPv6Connectivity } = require('./scanner');
const { updateWhoisForDomain } = require('./whois');
const { SCAN_STATUS, SCAN_TRIGGER, CERT_EXPIRY_WARNING_DAYS } = require('./constants');
const { getSetting, initSettings } = require('./settings-service');

// ─── PostgreSQL advisory locks (replaces Redis) ───
function lockKeyToId(key) {
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    hash = ((hash << 5) - hash + key.charCodeAt(i)) | 0;
  }
  return hash;
}

async function acquireLock(key) {
  const id = lockKeyToId(key);
  const result = await query('SELECT pg_try_advisory_lock($1) AS acquired', [id]);
  return result.rows[0].acquired;
}

async function releaseLock(key) {
  const id = lockKeyToId(key);
  await query('SELECT pg_advisory_unlock($1)', [id]);
}

async function checkScheduledScans() {
  try {
    // Re-check IPv6 connectivity each scan cycle
    await checkIPv6Connectivity();

    const domains = await query(`
      SELECT d.* FROM domains d
      WHERE d.enabled = TRUE
        AND (
          NOT EXISTS (SELECT 1 FROM scans WHERE domain_id = d.id)
          OR (SELECT started_at FROM scans WHERE domain_id = d.id ORDER BY started_at DESC LIMIT 1)
            < NOW() - (d.scan_interval_minutes || ' minutes')::INTERVAL
        )
    `);

    const runningScans = await query('SELECT COUNT(*) as count FROM scans WHERE status = $1', [SCAN_STATUS.RUNNING]);
    let running = parseInt(runningScans.rows[0].count);
    const maxConcurrentScans = parseInt(await getSetting('max_concurrent_scans'), 10) || 3;

    // Update worker heartbeat
    await query("INSERT INTO app_settings (key, value) VALUES ('worker_last_scan_check', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [new Date().toISOString()]);

    for (const domain of domains.rows) {
      if (running >= maxConcurrentScans) break;

      const lockKey = `scan:${domain.id}`;
      if (!(await acquireLock(lockKey))) continue;

      try {
        const scanResult = await query(
          'INSERT INTO scans (domain_id, trigger) VALUES ($1, $2) RETURNING id',
          [domain.id, SCAN_TRIGGER.SCHEDULED]
        );

        console.log(`[WORKER] Scheduled scan for ${domain.domain}`);
        running++;

        performScan(domain, scanResult.rows[0].id)
          .catch(err => console.error(`[WORKER] Scan error for ${domain.domain}:`, err.message))
          .finally(() => releaseLock(lockKey));
      } catch (err) {
        await releaseLock(lockKey);
        console.error(`[WORKER] Error starting scan for ${domain.domain}:`, err.message);
      }
    }
  } catch (err) {
    console.error('[WORKER] Schedule check error:', err.message);
  }
}

async function checkWhoisUpdates() {
  try {
    const lockKey = 'whois_check';
    if (!(await acquireLock(lockKey))) return;

    try {
      await query("INSERT INTO app_settings (key, value) VALUES ('worker_last_whois_check', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [new Date().toISOString()]);
      const domains = await query(`
        SELECT d.* FROM domains d
        WHERE d.enabled = TRUE
          AND (
            NOT EXISTS (SELECT 1 FROM domain_whois WHERE domain_id = d.id)
            OR (SELECT last_checked FROM domain_whois WHERE domain_id = d.id) < NOW() - INTERVAL '7 days'
          )
        LIMIT 10
      `);

      for (const domain of domains.rows) {
        await updateWhoisForDomain(domain);
        // Rate limit: wait 5s between whois queries
        await new Promise(r => setTimeout(r, 5000));
      }
    } finally {
      await releaseLock(lockKey);
    }
  } catch (err) {
    console.error('[WORKER] Whois check error:', err.message);
  }
}

async function cleanupOldData() {
  try {
    const lockKey = 'cleanup';
    if (!(await acquireLock(lockKey))) return;

    try {
      await query("INSERT INTO app_settings (key, value) VALUES ('worker_last_cleanup', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [new Date().toISOString()]);
      const result = await query("DELETE FROM health_checks WHERE checked_at < NOW() - INTERVAL '90 days'");
      if (result.rowCount > 0) console.log(`[WORKER] Cleaned up ${result.rowCount} old health checks`);

      const wdResult = await query("DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - INTERVAL '30 days'");
      if (wdResult.rowCount > 0) console.log(`[WORKER] Cleaned up ${wdResult.rowCount} old webhook deliveries`);
    } finally {
      await releaseLock(lockKey);
    }
  } catch (err) {
    console.error('[WORKER] Cleanup error:', err.message);
  }
}

async function checkDomainExpiry() {
  try {
    const { sendPushToUser, sendEmail } = require('./notifier');
    const expiring = await query(`
      SELECT dw.*, d.domain, d.id as domain_id
      FROM domain_whois dw
      JOIN domains d ON d.id = dw.domain_id
      WHERE dw.expiry_date IS NOT NULL
        AND dw.expiry_date < NOW() + INTERVAL '90 days'
        AND dw.expiry_date > NOW()
    `);

    for (const domain of expiring.rows) {
      const daysUntil = Math.ceil((new Date(domain.expiry_date) - new Date()) / (1000 * 60 * 60 * 24));
      const shouldWarn = [90, 30, 14, 7].some(d => daysUntil <= d && daysUntil > d - 1);
      if (!shouldWarn) continue;

      const users = await query(`
        SELECT u.id, u.email, ns.push_enabled, ns.email_enabled, ns.notify_on_domain_expiry
        FROM users u JOIN notification_settings ns ON ns.user_id = u.id
        WHERE ns.notify_on_domain_expiry = TRUE
      `);

      for (const user of users.rows) {
        const msg = { title: `Domain Expiry Warning`, body: `${domain.domain} expires in ${daysUntil} days (${new Date(domain.expiry_date).toLocaleDateString()})` };
        if (user.push_enabled) await sendPushToUser(user.id, msg);
        if (user.email_enabled && user.email) {
          try { await sendEmail(user.email, msg.title, `<h2>${msg.title}</h2><p>${msg.body}</p>`); } catch (e) {}
        }
      }
    }
  } catch (err) {
    console.error('[WORKER] Expiry check error:', err.message);
  }
}

async function checkCertExpiry() {
  try {
    const lockKey = 'cert_expiry_check';
    if (!(await acquireLock(lockKey))) return;

    try {
      await query("INSERT INTO app_settings (key, value) VALUES ('worker_last_cert_expiry_check', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [new Date().toISOString()]);

      const { sendPushToUser, sendEmail, deliverWebhook } = require('./notifier');

      const expiring = await query(`
        SELECT DISTINCT ON (dr.id)
          dr.id as record_id, dr.name, dr.record_type, dr.value,
          d.id as domain_id, d.domain,
          hc.ssl_expires_at, hc.ssl_valid, hc.ssl_error
        FROM dns_records dr
        JOIN domains d ON d.id = dr.domain_id
        JOIN LATERAL (
          SELECT ssl_expires_at, ssl_valid, ssl_error
          FROM health_checks WHERE record_id = dr.id
          ORDER BY checked_at DESC LIMIT 1
        ) hc ON TRUE
        WHERE dr.removed_at IS NULL
          AND d.enabled = TRUE
          AND hc.ssl_expires_at IS NOT NULL
          AND hc.ssl_expires_at > NOW()
          AND hc.ssl_expires_at < NOW() + INTERVAL '30 days'
      `);

      for (const record of expiring.rows) {
        const daysUntil = Math.ceil((new Date(record.ssl_expires_at) - new Date()) / (1000 * 60 * 60 * 24));
        const shouldWarn = CERT_EXPIRY_WARNING_DAYS.some(d => daysUntil <= d && daysUntil > d - 1);
        if (!shouldWarn) continue;

        const fqdn = record.name === '@' ? record.domain : `${record.name}.${record.domain}`;

        // Notify users who opted in
        const users = await query(`
          SELECT u.id, u.email, ns.push_enabled, ns.email_enabled
          FROM users u JOIN notification_settings ns ON ns.user_id = u.id
          WHERE ns.notify_on_cert_expiry = TRUE
        `);

        for (const user of users.rows) {
          const msg = { title: 'SSL Certificate Expiry Warning', body: `Certificate for ${fqdn} expires in ${daysUntil} day${daysUntil !== 1 ? 's' : ''} (${new Date(record.ssl_expires_at).toLocaleDateString()})` };
          if (user.push_enabled) await sendPushToUser(user.id, msg);
          if (user.email_enabled && user.email) {
            try { await sendEmail(user.email, msg.title, `<h2>${msg.title}</h2><p>${msg.body}</p>`); } catch (e) {}
          }
        }

        // Send webhooks
        const webhooks = await query('SELECT * FROM webhooks WHERE enabled = TRUE');
        for (const webhook of webhooks.rows) {
          let events;
          try { events = typeof webhook.events === 'string' ? JSON.parse(webhook.events) : (webhook.events || []); } catch (e) { events = []; }
          if (events.includes('cert.expiry_warning')) {
            await deliverWebhook(webhook, 'cert.expiry_warning', {
              domain: record.domain,
              record: { type: record.record_type, name: record.name, value: record.value },
              ssl_expires_at: record.ssl_expires_at,
              days_until_expiry: daysUntil,
            });
          }
        }
      }

      if (expiring.rows.length > 0) console.log(`[WORKER] Found ${expiring.rows.length} certificates expiring within 30 days`);
    } finally {
      await releaseLock(lockKey);
    }
  } catch (err) {
    console.error('[WORKER] Cert expiry check error:', err.message);
  }
}

function startWorker() {
  console.log('[WORKER] Starting background worker...');

  // Check scheduled scans every 5 minutes
  setInterval(checkScheduledScans, 5 * 60 * 1000);
  // Check whois weekly (check every 6 hours, but whois func only runs if needed)
  setInterval(checkWhoisUpdates, 6 * 60 * 60 * 1000);
  // Cleanup daily (check every hour)
  setInterval(cleanupOldData, 60 * 60 * 1000);
  // Check domain expiry every 12 hours
  setInterval(checkDomainExpiry, 12 * 60 * 60 * 1000);
  // Check certificate expiry every 12 hours
  setInterval(checkCertExpiry, 12 * 60 * 60 * 1000);

  // Run immediately on start
  setTimeout(checkScheduledScans, 10000);
  setTimeout(checkWhoisUpdates, 30000);
  setTimeout(checkCertExpiry, 45000);

  console.log('[WORKER] Background worker running');
}

module.exports = { startWorker };

// Allow standalone execution
if (require.main === module) {
  if (!process.env.DB_PASSWORD) { console.error('[FATAL] Missing DB_PASSWORD'); process.exit(1); }
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) { console.error('[FATAL] Missing/short SESSION_SECRET'); process.exit(1); }
  if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length < 32) { console.error('[FATAL] Missing/short ENCRYPTION_KEY'); process.exit(1); }

  initSchema().then(() => initSettings()).then(() => startWorker()).catch(err => {
    console.error('[FATAL]', err.message || err);
    if (err.stack) console.error(err.stack);
    process.exit(1);
  });
}
