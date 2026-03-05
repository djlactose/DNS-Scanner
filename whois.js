'use strict';

const { execFile } = require('node:child_process');
const { query } = require('./db');

const EXPIRY_PATTERNS = [
  /Registry Expiry Date:\s*(.+)/i,
  /Expir(?:y|ation) Date:\s*(.+)/i,
  /paid-till:\s*(.+)/i,
  /Expiration Time:\s*(.+)/i,
  /expire:\s*(.+)/i,
  /Valid Until:\s*(.+)/i,
];

const REGISTRAR_PATTERNS = [
  /Registrar:\s*(.+)/i,
  /Sponsoring Registrar:\s*(.+)/i,
  /registrar:\s*(.+)/i,
];

function parseWhois(raw) {
  let expiry = null;
  let registrar = null;

  for (const pattern of EXPIRY_PATTERNS) {
    const match = raw.match(pattern);
    if (match) {
      const parsed = new Date(match[1].trim());
      if (!isNaN(parsed.getTime())) { expiry = parsed; break; }
    }
  }

  for (const pattern of REGISTRAR_PATTERNS) {
    const match = raw.match(pattern);
    if (match) { registrar = match[1].trim(); break; }
  }

  return { expiry, registrar };
}

async function checkWhois(domain) {
  return new Promise((resolve, reject) => {
    execFile('whois', [domain], { timeout: 30000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`Whois failed: ${err.message}`));
      const raw = stdout || '';
      const parsed = parseWhois(raw);
      resolve({ raw: raw.substring(0, 10000), ...parsed });
    });
  });
}

async function updateWhoisForDomain(domainRow) {
  try {
    const result = await checkWhois(domainRow.domain);
    await query(
      `INSERT INTO domain_whois (domain_id, registrar, expiry_date, last_checked, raw_whois)
       VALUES ($1, $2, $3, NOW(), $4)
       ON CONFLICT (domain_id) DO UPDATE SET
         registrar = COALESCE($2, domain_whois.registrar),
         expiry_date = COALESCE($3, domain_whois.expiry_date),
         last_checked = NOW(),
         raw_whois = $4`,
      [domainRow.id, result.registrar, result.expiry, result.raw]
    );
    console.log(`[WHOIS] Updated for ${domainRow.domain}: expires ${result.expiry?.toISOString() || 'unknown'}`);
    return result;
  } catch (err) {
    console.error(`[WHOIS] Error for ${domainRow.domain}:`, err.message);
    return null;
  }
}

module.exports = { checkWhois, updateWhoisForDomain };
