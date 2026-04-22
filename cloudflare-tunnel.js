'use strict';

const dns = require('node:dns');
const { query } = require('./db');
const { getSetting } = require('./settings-service');

const TUNNEL_UUID_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.cfargotunnel\.com$/i;

/**
 * Extract a Cloudflare Tunnel UUID from a CNAME value like "{uuid}.cfargotunnel.com".
 * Returns the UUID string or null.
 */
function detectTunnelFromCNAME(value) {
  if (!value) return null;
  const match = value.match(TUNNEL_UUID_RE);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Walk a CNAME chain looking for a cfargotunnel.com hostname. Returns the
 * tunnel UUID if found, else null. Used when a record's direct value isn't
 * a tunnel but it CNAMEs through another record that ultimately points at
 * one (e.g. remote.example.com -> dev.example.com -> {uuid}.cfargotunnel.com).
 */
async function detectTunnelInChain(hostname, maxDepth = 5) {
  let current = hostname;
  const seen = new Set();
  for (let i = 0; i < maxDepth; i++) {
    if (seen.has(current)) return null;
    seen.add(current);
    const uuid = detectTunnelFromCNAME(current);
    if (uuid) return uuid;
    try {
      const cnames = await dns.promises.resolveCname(current);
      if (!cnames.length) return null;
      current = cnames[0];
    } catch (e) {
      return null;
    }
  }
  return null;
}

/**
 * Fetch tunnel status from the Cloudflare API.
 * Requires cloudflare_api_token and cloudflare_account_id settings.
 */
async function fetchTunnelStatus(tunnelId) {
  const token = await getSetting('cloudflare_api_token');
  const accountId = await getSetting('cloudflare_account_id');

  if (!token || !accountId) {
    return { available: false, reason: 'missing_credentials' };
  }

  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}`,
      { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
    );
    const data = await res.json();

    if (!data.success) {
      const errMsg = data.errors?.map(e => e.message).join(', ') || 'Unknown API error';
      console.log(`[TUNNEL] API error for ${tunnelId}: ${errMsg}`);
      return { available: false, reason: 'api_error', error: errMsg };
    }

    const tunnel = data.result;
    return {
      available: true,
      status: tunnel.status || 'unknown',
      connections: tunnel.connections || [],
      name: tunnel.name || null,
    };
  } catch (e) {
    console.log(`[TUNNEL] Fetch failed for ${tunnelId}: ${e.message}`);
    return { available: false, reason: 'network_error', error: e.message };
  }
}

/**
 * Upsert a tunnel record and link it to a DNS record.
 */
async function syncTunnelRecord(recordId, tunnelUUID) {
  // Upsert tunnel
  const tunnelRes = await query(
    `INSERT INTO cloudflare_tunnels (tunnel_id) VALUES ($1)
     ON CONFLICT (tunnel_id) DO UPDATE SET tunnel_id = cloudflare_tunnels.tunnel_id
     RETURNING id`,
    [tunnelUUID]
  );
  const tunnelDbId = tunnelRes.rows[0].id;

  // Link record to tunnel
  await query(
    `INSERT INTO dns_record_tunnels (record_id, tunnel_id, detected_method)
     VALUES ($1, $2, 'auto')
     ON CONFLICT (record_id, tunnel_id) DO NOTHING`,
    [recordId, tunnelDbId]
  );

  return tunnelDbId;
}

/**
 * Check tunnel health via API. Updates the cloudflare_tunnels row.
 * Returns { source: 'api'|'fallback', status, connections?, name? }
 */
async function checkTunnelHealth(tunnelUUID) {
  const result = await fetchTunnelStatus(tunnelUUID);

  if (result.available) {
    // Update tunnel row with latest status
    const updateFields = [
      'status = $2',
      'connections = $3',
      'last_checked_at = NOW()',
    ];
    const params = [tunnelUUID, result.status, JSON.stringify(result.connections)];

    if (result.name) {
      updateFields.push(`tunnel_name = $${params.length + 1}`);
      params.push(result.name);
    }
    if (result.status === 'healthy') {
      updateFields.push('last_healthy_at = NOW()');
    }

    await query(
      `UPDATE cloudflare_tunnels SET ${updateFields.join(', ')} WHERE tunnel_id = $1`,
      params
    );

    return { source: 'api', status: result.status, connections: result.connections, name: result.name };
  }

  // API unavailable — update last_checked_at only
  await query(
    `UPDATE cloudflare_tunnels SET last_checked_at = NOW() WHERE tunnel_id = $1`,
    [tunnelUUID]
  );

  return { source: 'fallback', status: 'unknown', reason: result.reason };
}

/**
 * Get aggregate tunnel summary for the dashboard.
 */
async function getTunnelSummary() {
  const res = await query(`
    SELECT
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE status = 'healthy')::int AS healthy,
      COUNT(*) FILTER (WHERE status = 'degraded')::int AS degraded,
      COUNT(*) FILTER (WHERE status = 'down')::int AS down,
      COUNT(*) FILTER (WHERE status = 'unknown' OR status IS NULL)::int AS unknown
    FROM cloudflare_tunnels
  `);
  return res.rows[0] || { total: 0, healthy: 0, degraded: 0, down: 0, unknown: 0 };
}

/**
 * Get all tunnels with their associated records for a domain.
 */
async function getTunnelsForDomain(domainId) {
  const res = await query(`
    SELECT ct.tunnel_id AS tunnel_uuid, ct.tunnel_name, ct.status AS tunnel_status,
           ct.connections, ct.last_checked_at, ct.last_healthy_at,
           dr.id AS record_id, dr.name AS record_name, dr.value AS record_value
    FROM dns_record_tunnels drt
    JOIN cloudflare_tunnels ct ON ct.id = drt.tunnel_id
    JOIN dns_records dr ON dr.id = drt.record_id
    WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
    ORDER BY ct.tunnel_id, dr.name
  `, [domainId]);
  return res.rows;
}

module.exports = {
  detectTunnelFromCNAME,
  detectTunnelInChain,
  fetchTunnelStatus,
  syncTunnelRecord,
  checkTunnelHealth,
  getTunnelSummary,
  getTunnelsForDomain,
};
