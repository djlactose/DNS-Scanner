'use strict';

const Redis = require('ioredis');
const { query, initSchema } = require('./db');
const { performScan } = require('./scanner');
const { updateWhoisForDomain } = require('./whois');
const { SCAN_STATUS, SCAN_TRIGGER, MAX_CONCURRENT_SCANS } = require('./constants');

// Validate required env vars
if (!process.env.DB_PASSWORD) { console.error('[FATAL] Missing DB_PASSWORD'); process.exit(1); }
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) { console.error('[FATAL] Missing/short SESSION_SECRET'); process.exit(1); }
if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length < 32) { console.error('[FATAL] Missing/short ENCRYPTION_KEY'); process.exit(1); }

const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD || undefined,
  retryStrategy: (times) => Math.min(times * 500, 5000),
});

redis.on('error', (err) => console.error('[REDIS]', err.message));

async function acquireLock(key, ttlSeconds = 300) {
  const result = await redis.set(`lock:${key}`, Date.now(), 'EX', ttlSeconds, 'NX');
  return result === 'OK';
}

async function releaseLock(key) {
  await redis.del(`lock:${key}`);
}

async function checkScheduledScans() {
  try {
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

    for (const domain of domains.rows) {
      if (running >= MAX_CONCURRENT_SCANS) break;

      const lockKey = `scan:${domain.id}`;
      if (!(await acquireLock(lockKey, 300))) continue;

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
    if (!(await acquireLock(lockKey, 3600))) return;

    try {
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
    if (!(await acquireLock(lockKey, 600))) return;

    try {
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

async function start() {
  console.log('[WORKER] Starting background worker...');
  await initSchema();

  // Check scheduled scans every 5 minutes
  setInterval(checkScheduledScans, 5 * 60 * 1000);
  // Check whois weekly (check every 6 hours, but whois func only runs if needed)
  setInterval(checkWhoisUpdates, 6 * 60 * 60 * 1000);
  // Cleanup daily (check every hour)
  setInterval(cleanupOldData, 60 * 60 * 1000);
  // Check domain expiry every 12 hours
  setInterval(checkDomainExpiry, 12 * 60 * 60 * 1000);

  // Run immediately on start
  setTimeout(checkScheduledScans, 10000);
  setTimeout(checkWhoisUpdates, 30000);

  console.log('[WORKER] Background worker running');
}

start().catch(err => {
  console.error('[FATAL]', err.message || err);
  if (err.stack) console.error(err.stack);
  process.exit(1);
});
