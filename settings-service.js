'use strict';

const { query } = require('./db');
const { encrypt, decrypt } = require('./crypto-utils');

// ─── Settings definitions: single source of truth ───
const SETTINGS_DEFINITIONS = {
  // General
  registration_enabled:    { envVar: 'REGISTRATION_ENABLED',    default: 'true',        type: 'boolean', category: 'general',  label: 'Allow Registration',              sensitive: false, description: 'Allow new users to register accounts' },
  allow_private_ranges:    { envVar: 'ALLOW_PRIVATE_RANGES',    default: 'false',       type: 'boolean', category: 'general',  label: 'Allow Private IP Ranges',         sensitive: false, description: 'Allow scanning private/internal IP ranges (disables SSRF protection)' },
  max_domains:             { envVar: 'MAX_DOMAINS',             default: '50',          type: 'number',  category: 'general',  label: 'Maximum Domains',                 sensitive: false, description: 'Maximum number of domains that can be monitored' },

  // Authentication
  google_client_id:        { envVar: 'GOOGLE_CLIENT_ID',        default: '',            type: 'string',  category: 'auth',     label: 'Google Client ID',                sensitive: false, description: 'OAuth 2.0 Client ID for Google Sign-In' },
  google_client_secret:    { envVar: 'GOOGLE_CLIENT_SECRET',    default: '',            type: 'string',  category: 'auth',     label: 'Google Client Secret',            sensitive: true,  description: 'OAuth 2.0 Client Secret for Google Sign-In' },
  google_auth_enabled:     { envVar: null,                      default: 'true',        type: 'boolean', category: 'auth',     label: 'Enable Google Sign-In',           sensitive: false, description: 'Allow users to sign in with Google' },
  webauthn_rp_id:          { envVar: 'WEBAUTHN_RP_ID',          default: '',            type: 'string',  category: 'auth',     label: 'WebAuthn RP ID',                  sensitive: false, description: 'Relying Party ID for passkeys (auto-detected from hostname if blank)' },
  webauthn_rp_name:        { envVar: 'WEBAUTHN_RP_NAME',        default: 'DNS Scanner', type: 'string',  category: 'auth',     label: 'WebAuthn RP Name',                sensitive: false, description: 'Display name shown during passkey registration' },
  webauthn_origin:         { envVar: 'WEBAUTHN_ORIGIN',         default: '',            type: 'string',  category: 'auth',     label: 'WebAuthn Origin',                 sensitive: false, description: 'Expected origin for passkey verification (auto-detected if blank)' },

  // Scanner performance
  consecutive_failures_threshold: { envVar: null, default: '3',     type: 'number', category: 'scanner', label: 'Consecutive Failures Threshold', sensitive: false, description: 'Number of consecutive failed health checks before marking a record as dead' },
  health_check_timeout_ms:        { envVar: null, default: '10000', type: 'number', category: 'scanner', label: 'Health Check Timeout (ms)',      sensitive: false, description: 'Timeout in milliseconds for individual health checks' },
  scan_timeout_ms:                { envVar: null, default: '60000', type: 'number', category: 'scanner', label: 'Scan Timeout (ms)',              sensitive: false, description: 'Overall timeout in milliseconds for a full domain scan' },
  max_concurrent_checks:          { envVar: null, default: '10',    type: 'number', category: 'scanner', label: 'Max Concurrent Health Checks',   sensitive: false, description: 'Maximum number of health checks running in parallel' },
  max_concurrent_scans:           { envVar: null, default: '3',     type: 'number', category: 'scanner', label: 'Max Concurrent Scans',           sensitive: false, description: 'Maximum number of domain scans running in parallel' },

  // DNS Provider Integrations
  cloudflare_api_token:  { envVar: 'CLOUDFLARE_API_TOKEN',  default: '', type: 'string',  category: 'integrations', label: 'Cloudflare API Token',       sensitive: true,  description: 'API token with Zone:Read and DNS:Read permissions. Creates a complete zone export for Cloudflare-managed domains.' },
  route53_access_key:    { envVar: 'ROUTE53_ACCESS_KEY',    default: '', type: 'string',  category: 'integrations', label: 'AWS Access Key ID',          sensitive: true,  description: 'AWS access key for Route 53 DNS. Needs route53:ListHostedZones and route53:ListResourceRecordSets permissions.' },
  route53_secret_key:    { envVar: 'ROUTE53_SECRET_KEY',    default: '', type: 'string',  category: 'integrations', label: 'AWS Secret Access Key',      sensitive: true,  description: 'AWS secret key for Route 53 DNS.' },
  digitalocean_api_token: { envVar: 'DIGITALOCEAN_API_TOKEN', default: '', type: 'string', category: 'integrations', label: 'DigitalOcean API Token',    sensitive: true,  description: 'Personal access token for DigitalOcean DNS. Provides complete zone records for DO-managed domains.' },
};

// ─── In-memory cache ───
const CACHE_TTL_MS = 60_000;
const cache = new Map(); // key → { value, expiresAt }

function getCached(key) {
  const entry = cache.get(key);
  if (entry && Date.now() < entry.expiresAt) return entry.value;
  cache.delete(key);
  return undefined;
}

function setCache(key, value) {
  cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
}

function invalidateCache(key) {
  if (key) cache.delete(key);
  else cache.clear();
}

// ─── Core API ───

/**
 * Seed all defined settings from env vars into the database.
 * Uses ON CONFLICT DO NOTHING so existing DB values are never overwritten.
 */
async function initSettings() {
  for (const [key, def] of Object.entries(SETTINGS_DEFINITIONS)) {
    const envValue = def.envVar ? process.env[def.envVar] : null;
    const value = envValue != null && envValue !== '' ? envValue : def.default;

    // For sensitive values, encrypt before storing
    const storeValue = def.sensitive && value ? encrypt(value) : value;

    await query(
      `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO NOTHING`,
      [key, storeValue]
    );
  }
  // Pre-warm cache
  await loadAllIntoCache();
}

/**
 * Load all settings into cache in a single query.
 */
async function loadAllIntoCache() {
  const result = await query(`SELECT key, value FROM app_settings`);
  for (const row of result.rows) {
    const def = SETTINGS_DEFINITIONS[row.key];
    if (def && def.sensitive && row.value) {
      try {
        setCache(row.key, decrypt(row.value));
      } catch {
        setCache(row.key, row.value); // fallback if not encrypted (legacy)
      }
    } else {
      setCache(row.key, row.value);
    }
  }
}

/**
 * Get a single setting value.
 * Returns the cached/DB value, or the default from definitions.
 */
async function getSetting(key) {
  const def = SETTINGS_DEFINITIONS[key];

  // Check cache first
  const cached = getCached(key);
  if (cached !== undefined) return cached;

  // Query DB
  const result = await query(`SELECT value FROM app_settings WHERE key = $1`, [key]);
  if (result.rows.length > 0) {
    let value = result.rows[0].value;
    if (def && def.sensitive && value) {
      try { value = decrypt(value); } catch { /* legacy unencrypted value */ }
    }
    setCache(key, value);
    return value;
  }

  // Return default
  const defaultValue = def ? def.default : null;
  if (defaultValue !== null) setCache(key, defaultValue);
  return defaultValue;
}

/**
 * Set a single setting value. Validates against definitions.
 */
async function setSetting(key, value) {
  const def = SETTINGS_DEFINITIONS[key];
  if (!def) throw new Error(`Unknown setting: ${key}`);

  // Validate
  if (def.type === 'number') {
    const num = Number(value);
    if (isNaN(num)) throw new Error(`Setting ${key} must be a number`);
    value = String(num);
  } else if (def.type === 'boolean') {
    if (value !== 'true' && value !== 'false') {
      throw new Error(`Setting ${key} must be 'true' or 'false'`);
    }
  }

  const storeValue = def.sensitive && value ? encrypt(value) : value;

  await query(
    `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
     ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
    [key, storeValue]
  );

  // Update cache with the plain (decrypted) value
  setCache(key, value);
  return value;
}

/**
 * Get all settings grouped by category for the admin UI.
 * Sensitive values are masked.
 */
async function getAllSettings() {
  // Refresh cache
  await loadAllIntoCache();

  const grouped = {};
  for (const [key, def] of Object.entries(SETTINGS_DEFINITIONS)) {
    if (!grouped[def.category]) grouped[def.category] = [];

    let value = getCached(key);
    if (value === undefined) value = def.default;

    grouped[def.category].push({
      key,
      value: def.sensitive && value ? '••••••••' : value,
      hasValue: def.sensitive ? !!(value && value !== def.default) : undefined,
      label: def.label,
      type: def.type,
      sensitive: def.sensitive,
      description: def.description,
    });
  }
  return grouped;
}

module.exports = {
  SETTINGS_DEFINITIONS,
  initSettings,
  getSetting,
  setSetting,
  getAllSettings,
  invalidateCache,
};
