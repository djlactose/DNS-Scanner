'use strict';

const { Pool } = require('pg');

let pool;

function getPool() {
  if (!pool) {
    pool = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      database: process.env.DB_NAME || 'dnsscanner',
      user: process.env.DB_USER || 'dnsscanner',
      password: process.env.DB_PASSWORD,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    pool.on('error', (err) => {
      console.error('[DB] Unexpected pool error:', err.message);
    });
  }
  return pool;
}

function query(text, params) {
  return getPool().query(text, params);
}

async function ensureDatabase() {
  const dbName = process.env.DB_NAME || 'dnsscanner';
  const dbUser = process.env.DB_USER || 'dnsscanner';
  const adminPool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: 'template1',
    user: dbUser,
    password: process.env.DB_PASSWORD,
    max: 1,
    connectionTimeoutMillis: 5000,
  });
  try {
    const { rows } = await adminPool.query(
      'SELECT 1 FROM pg_database WHERE datname = $1', [dbName]
    );
    if (rows.length === 0) {
      await adminPool.query(`CREATE DATABASE "${dbName}"`);
      console.log(`[DB] Created database "${dbName}"`);
    }
  } finally {
    await adminPool.end();
  }
}

async function initSchema() {
  await ensureDatabase();
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(30) UNIQUE NOT NULL,
        email VARCHAR(255),
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(10) NOT NULL DEFAULT 'viewer',
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS "session" (
        "sid" VARCHAR NOT NULL COLLATE "default",
        "sess" JSON NOT NULL,
        "expire" TIMESTAMPTZ NOT NULL,
        PRIMARY KEY ("sid")
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire")`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS domains (
        id SERIAL PRIMARY KEY,
        domain VARCHAR(253) UNIQUE NOT NULL,
        display_name VARCHAR(255),
        scan_interval_minutes INTEGER DEFAULT 360,
        enabled BOOLEAN DEFAULT TRUE,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS dns_records (
        id SERIAL PRIMARY KEY,
        domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
        record_type VARCHAR(10) NOT NULL,
        name VARCHAR(255) NOT NULL,
        value TEXT NOT NULL,
        priority INTEGER,
        ttl INTEGER,
        first_seen TIMESTAMPTZ DEFAULT NOW(),
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        removed_at TIMESTAMPTZ,
        takeover_risk BOOLEAN DEFAULT FALSE,
        dismissed BOOLEAN DEFAULT FALSE,
        dismissed_by INTEGER REFERENCES users(id),
        UNIQUE(domain_id, record_type, name, value)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS health_checks (
        id SERIAL PRIMARY KEY,
        record_id INTEGER REFERENCES dns_records(id) ON DELETE CASCADE,
        checked_at TIMESTAMPTZ DEFAULT NOW(),
        status VARCHAR(20) NOT NULL,
        status_code INTEGER,
        response_ms INTEGER,
        error_message TEXT,
        check_method VARCHAR(20),
        ports_open JSONB DEFAULT '[]',
        ssl_valid BOOLEAN,
        ssl_expires_at TIMESTAMPTZ,
        ssl_error TEXT,
        propagation_results JSONB
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_health_checks_record ON health_checks(record_id, checked_at DESC)`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY,
        domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
        started_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        status VARCHAR(20) DEFAULT 'running',
        records_found INTEGER DEFAULT 0,
        records_alive INTEGER DEFAULT 0,
        records_dead INTEGER DEFAULT 0,
        trigger VARCHAR(20) DEFAULT 'manual',
        triggered_by INTEGER REFERENCES users(id)
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain_id, started_at DESC)`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS dns_changes (
        id SERIAL PRIMARY KEY,
        record_id INTEGER REFERENCES dns_records(id) ON DELETE CASCADE,
        domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
        record_type VARCHAR(10) NOT NULL,
        name VARCHAR(255) NOT NULL,
        old_value TEXT,
        new_value TEXT,
        changed_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_dns_changes_domain ON dns_changes(domain_id, changed_at DESC)`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS domain_whois (
        id SERIAL PRIMARY KEY,
        domain_id INTEGER UNIQUE REFERENCES domains(id) ON DELETE CASCADE,
        registrar TEXT,
        expiry_date TIMESTAMPTZ,
        last_checked TIMESTAMPTZ,
        raw_whois TEXT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tags (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL,
        color VARCHAR(7) DEFAULT '#3b82f6',
        created_by INTEGER REFERENCES users(id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS domain_tags (
        domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
        tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
        PRIMARY KEY(domain_id, tag_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS notification_settings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        email_enabled BOOLEAN DEFAULT FALSE,
        push_enabled BOOLEAN DEFAULT FALSE,
        notify_on_dead BOOLEAN DEFAULT TRUE,
        notify_on_recovery BOOLEAN DEFAULT TRUE,
        notify_on_takeover_risk BOOLEAN DEFAULT TRUE,
        notify_on_dns_change BOOLEAN DEFAULT TRUE,
        notify_on_domain_expiry BOOLEAN DEFAULT TRUE,
        notify_tags_only JSONB
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        endpoint TEXT NOT NULL,
        keys_p256dh TEXT NOT NULL,
        keys_auth TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS smtp_config (
        id SERIAL PRIMARY KEY,
        smtp_host VARCHAR(255),
        smtp_port INTEGER DEFAULT 587,
        smtp_user VARCHAR(255),
        smtp_pass TEXT,
        smtp_secure BOOLEAN DEFAULT TRUE
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(64) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_reset_tokens_hash ON password_reset_tokens(token_hash)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON password_reset_tokens(user_id)`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key VARCHAR(100) PRIMARY KEY,
        value TEXT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS webhooks (
        id SERIAL PRIMARY KEY,
        created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        url TEXT NOT NULL,
        secret VARCHAR(255),
        events JSONB DEFAULT '[]',
        enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS webhook_deliveries (
        id SERIAL PRIMARY KEY,
        webhook_id INTEGER REFERENCES webhooks(id) ON DELETE CASCADE,
        event_type VARCHAR(50) NOT NULL,
        payload JSONB,
        response_status INTEGER,
        response_body TEXT,
        delivered_at TIMESTAMPTZ DEFAULT NOW(),
        attempts INTEGER DEFAULT 1
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries ON webhook_deliveries(webhook_id, delivered_at DESC)`);

    // ─── User invites ───
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_invites (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        role VARCHAR(10) NOT NULL DEFAULT 'viewer',
        token_hash VARCHAR(64) NOT NULL,
        invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        accepted BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_user_invites_token ON user_invites(token_hash)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_user_invites_email ON user_invites(email)`);

    // ─── WebAuthn / Passkey tables ───
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_credentials (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        credential_id TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        counter BIGINT DEFAULT 0,
        device_type VARCHAR(20),
        backed_up BOOLEAN DEFAULT FALSE,
        transports JSONB,
        name VARCHAR(100),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_used_at TIMESTAMPTZ
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_user_credentials_user ON user_credentials(user_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_user_credentials_cred_id ON user_credentials(credential_id)`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id SERIAL PRIMARY KEY,
        session_id VARCHAR(255) NOT NULL,
        challenge TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(20) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_session ON webauthn_challenges(session_id)`);

    // ─── Add Google OAuth and passkey columns to users ───
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255)`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS passkey_mode VARCHAR(20) DEFAULT 'either'`);
    await client.query(`DO $$ BEGIN ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL; EXCEPTION WHEN others THEN NULL; END $$`);
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL`);

    await client.query('COMMIT');
    console.log('[DB] Schema initialized');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { getPool, query, initSchema };
