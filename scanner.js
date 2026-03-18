'use strict';

const dns = require('node:dns');
const net = require('node:net');
const tls = require('node:tls');
const { execFile } = require('node:child_process');
const { query } = require('./db');
const { checkTakeover } = require('./takeover');
const { checkPropagation } = require('./propagation');
const {
  RECORD_TYPES, HEALTH_STATUS, SCAN_STATUS, SKIPPED_RECORD_TYPES,
  COMMON_PORTS, MX_PORTS, PRIVATE_RANGES_V4, COMMON_SUBDOMAINS,
} = require('./constants');
const { getSetting } = require('./settings-service');

// ─── Runtime settings (refreshed at the start of each scan) ───
let _allowPrivateRanges = false;
let _healthCheckTimeoutMs = 10000;
let _scanTimeoutMs = 60000;
let _maxConcurrentChecks = 10;
let _consecutiveFailuresThreshold = 3;

async function refreshScannerSettings() {
  _allowPrivateRanges = (await getSetting('allow_private_ranges')) === 'true';
  _healthCheckTimeoutMs = parseInt(await getSetting('health_check_timeout_ms'), 10) || 10000;
  _scanTimeoutMs = parseInt(await getSetting('scan_timeout_ms'), 10) || 60000;
  _maxConcurrentChecks = parseInt(await getSetting('max_concurrent_checks'), 10) || 10;
  _consecutiveFailuresThreshold = parseInt(await getSetting('consecutive_failures_threshold'), 10) || 3;
}

// ─── IPv6 connectivity detection ───
let _hasIPv6 = null; // null = untested, true/false after check

async function checkIPv6Connectivity() {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(3000);
    const done = (result) => {
      socket.destroy();
      _hasIPv6 = result;
      console.log(`[SCANNER] IPv6 connectivity: ${result ? 'available' : 'unavailable'}`);
      // Persist to app_settings (non-critical)
      query(
        "INSERT INTO app_settings (key, value) VALUES ('ipv6_available', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        [String(result)]
      ).catch(() => {});
      resolve(result);
    };
    socket.connect(53, '2001:4860:4860::8888', () => done(true));
    socket.on('error', () => done(false));
    socket.on('timeout', () => done(false));
  });
}

function hasIPv6() {
  return _hasIPv6;
}

class Semaphore {
  constructor(max) { this.max = max; this.count = 0; this.queue = []; }
  async acquire() {
    if (this.count < this.max) { this.count++; return; }
    return new Promise(resolve => this.queue.push(resolve));
  }
  release() {
    this.count--;
    if (this.queue.length > 0) { this.count++; this.queue.shift()(); }
  }
}

function isPrivateIP(ip) {
  if (_allowPrivateRanges) return false;
  if (ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;
  // Handle IPv4-mapped IPv6 (::ffff:10.0.0.1)
  let v4 = ip;
  if (ip.startsWith('::ffff:')) v4 = ip.slice(7);
  const parts = v4.split('.').map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 0) return true;
  return false;
}

async function attemptAXFR(domain) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve([]), 15000);
    try {
      dns.resolveNs(domain, (err, nsRecords) => {
        if (err || !nsRecords?.length) { clearTimeout(timeout); return resolve([]); }
        const ns = nsRecords[0];
        execFile('dig', ['@' + ns, domain, 'AXFR', '+short', '+time=10'], { timeout: 15000 }, (err, stdout) => {
          clearTimeout(timeout);
          if (err || !stdout) return resolve([]);
          const records = [];
          const lines = stdout.trim().split('\n').filter(Boolean);
          for (const line of lines) {
            const parts = line.split(/\s+/);
            if (parts.length >= 4) {
              const name = parts[0].replace(/\.$/, '');
              const type = parts[3];
              const value = parts.slice(4).join(' ').replace(/\.$/, '');
              if (RECORD_TYPES.includes(type) && value) {
                records.push({ name, type, value, ttl: parseInt(parts[1]) || null, priority: type === 'MX' ? parseInt(parts[4]) : null });
              }
            }
          }
          resolve(records);
        });
      });
    } catch (e) { clearTimeout(timeout); resolve([]); }
  });
}

async function enumerateDNS(domain) {
  const records = [];
  const resolver = new dns.Resolver();
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  // Try AXFR first
  const axfrRecords = await attemptAXFR(domain);
  if (axfrRecords.length > 0) {
    console.log(`[SCANNER] AXFR successful for ${domain}: ${axfrRecords.length} records`);
    records.push(...axfrRecords);
  }

  // Always do per-type enumeration as well
  for (const type of RECORD_TYPES) {
    try {
      let results;
      switch (type) {
        case 'A':
          results = await dns.promises.resolve4(domain);
          for (const ip of results) records.push({ name: '@', type: 'A', value: ip });
          break;
        case 'AAAA':
          results = await dns.promises.resolve6(domain);
          for (const ip of results) records.push({ name: '@', type: 'AAAA', value: ip });
          break;
        case 'CNAME':
          try {
            results = await dns.promises.resolveCname(domain);
            for (const cname of results) records.push({ name: '@', type: 'CNAME', value: cname });
          } catch (e) { /* CNAME often doesn't exist at apex */ }
          break;
        case 'MX':
          results = await dns.promises.resolveMx(domain);
          for (const mx of results) {
            if (mx.exchange) records.push({ name: '@', type: 'MX', value: mx.exchange, priority: mx.priority });
          }
          break;
        case 'TXT':
          results = await dns.promises.resolveTxt(domain);
          for (const txt of results) records.push({ name: '@', type: 'TXT', value: txt.join('') });
          break;
        case 'NS':
          results = await dns.promises.resolveNs(domain);
          for (const ns of results) records.push({ name: '@', type: 'NS', value: ns });
          break;
        case 'SRV':
          try {
            results = await dns.promises.resolveSrv(domain);
            for (const srv of results) records.push({ name: '@', type: 'SRV', value: `${srv.name}:${srv.port}`, priority: srv.priority });
          } catch (e) { /* SRV often doesn't exist */ }
          break;
        case 'CAA':
          try {
            results = await dns.promises.resolveCaa(domain);
            for (const caa of results) records.push({ name: '@', type: 'CAA', value: `${caa.critical} ${caa.issue || caa.issuewild || caa.iodef || ''}` });
          } catch (e) { /* CAA often doesn't exist */ }
          break;
        case 'SOA':
          try {
            results = await dns.promises.resolveSoa(domain);
            if (results) records.push({ name: '@', type: 'SOA', value: `${results.nsname} ${results.hostmaster}` });
          } catch (e) {}
          break;
      }
    } catch (e) {
      // Record type doesn't exist for this domain
    }
  }

  // Enumerate common subdomains for A, AAAA, CNAME, TXT records
  const subdomainResults = await Promise.allSettled(
    COMMON_SUBDOMAINS.map(async (sub) => {
      const fqdn = `${sub}.${domain}`;
      const subRecords = [];
      // CNAME check first
      try {
        const cnames = await dns.promises.resolveCname(fqdn);
        for (const cname of cnames) subRecords.push({ name: sub, type: 'CNAME', value: cname });
      } catch (e) { /* no CNAME for this subdomain */ }
      // A records (only if no CNAME found — CNAME and A are mutually exclusive)
      if (!subRecords.some(r => r.type === 'CNAME')) {
        try {
          const ips = await dns.promises.resolve4(fqdn);
          for (const ip of ips) subRecords.push({ name: sub, type: 'A', value: ip });
        } catch (e) { /* no A record */ }
        try {
          const ips = await dns.promises.resolve6(fqdn);
          for (const ip of ips) subRecords.push({ name: sub, type: 'AAAA', value: ip });
        } catch (e) { /* no AAAA record */ }
      }
      // TXT records for DNS-specific subdomains
      if (sub.startsWith('_')) {
        try {
          const txts = await dns.promises.resolveTxt(fqdn);
          for (const txt of txts) subRecords.push({ name: sub, type: 'TXT', value: txt.join('') });
        } catch (e) { /* no TXT record */ }
      }
      return subRecords;
    })
  );
  for (const result of subdomainResults) {
    if (result.status === 'fulfilled') records.push(...result.value);
  }

  // Deduplicate
  const seen = new Set();
  return records.filter(r => {
    const key = `${r.type}:${r.name}:${r.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function tcpCheck(host, port, timeoutMs = _healthCheckTimeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    const done = (result) => { socket.destroy(); resolve(result); };
    socket.connect(port, host, () => done(true));
    socket.on('error', () => done(false));
    socket.on('timeout', () => done(false));
  });
}

async function httpCheck(host, port, useHttps = false) {
  const timeout = _healthCheckTimeoutMs;
  const protocol = useHttps ? 'https' : 'http';
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(`${protocol}://${host}:${port}/`, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'manual',
      headers: { 'User-Agent': 'DNS-Scanner/1.0' },
    });
    clearTimeout(timer);
    return { alive: true, statusCode: response.status };
  } catch (e) {
    // Connection refused or timeout means server might still be alive if it responded at TCP level
    return { alive: false, statusCode: null };
  }
}

async function getSSLInfo(host, port = 443) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: _healthCheckTimeoutMs }, () => {
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        socket.destroy();
        if (!cert || !cert.valid_to) return resolve(null);
        resolve({
          valid: authorized,
          expires: new Date(cert.valid_to),
          issuer: cert.issuer?.O,
          error: authorized ? null : socket.authorizationError,
        });
      });
      socket.on('error', () => { socket.destroy(); resolve(null); });
      socket.on('timeout', () => { socket.destroy(); resolve(null); });
    } catch (e) { resolve(null); }
  });
}

async function icmpPing(host) {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';
    const isIPv6 = host.includes(':');
    const cmd = isWin ? 'ping' : (isIPv6 ? 'ping6' : 'ping');
    const args = isWin
      ? [isIPv6 ? '-6' : '-4', '-n', '1', '-w', '5000', host]
      : ['-c', '1', '-W', '5', host];
    execFile(cmd, args, { timeout: _healthCheckTimeoutMs }, (err, stdout) => {
      if (err) return resolve(false);
      resolve(!stdout.includes('100% packet loss') && !stdout.includes('unreachable'));
    });
  });
}

async function dnsQueryCheck(nameserver) {
  return new Promise((resolve) => {
    const resolver = new dns.Resolver();
    resolver.setServers([nameserver]);
    resolver.resolve4('example.com', (err) => resolve(!err));
  });
}

async function healthCheckRecord(record, domain) {
  const startTime = Date.now();
  const result = {
    status: HEALTH_STATUS.SKIPPED,
    statusCode: null,
    responseMs: null,
    errorMessage: null,
    checkMethod: null,
    portsOpen: [],
    sslValid: null,
    sslExpiresAt: null,
    sslError: null,
  };

  if (SKIPPED_RECORD_TYPES.includes(record.record_type)) {
    result.checkMethod = 'skipped';
    return result;
  }

  let targetIP = record.value;
  let targetHost = record.name === '@' ? domain : `${record.name}.${domain}`;

  // Resolve CNAME target
  if (record.record_type === 'CNAME') {
    try {
      const addrs = await dns.promises.resolve4(record.value);
      if (addrs.length > 0) targetIP = addrs[0];
      targetHost = record.value;
    } catch (e) {
      result.status = HEALTH_STATUS.DEAD;
      result.errorMessage = `CNAME target ${record.value} does not resolve`;
      result.checkMethod = 'dns_resolve';
      result.responseMs = Date.now() - startTime;
      return result;
    }
  }

  // SSRF check
  if (isPrivateIP(targetIP)) {
    result.status = HEALTH_STATUS.SKIPPED;
    result.errorMessage = 'Private IP range - scanning blocked';
    result.checkMethod = 'ssrf_blocked';
    return result;
  }

  // Skip AAAA health checks when host lacks IPv6 connectivity
  if (record.record_type === 'AAAA' && _hasIPv6 === false) {
    result.status = HEALTH_STATUS.NO_IPV6;
    result.errorMessage = 'Host lacks IPv6 connectivity - cannot verify AAAA record';
    result.checkMethod = 'ipv6_unavailable';
    result.responseMs = Date.now() - startTime;
    return result;
  }

  try {
    if (record.record_type === 'A' || record.record_type === 'AAAA' || record.record_type === 'CNAME') {
      // Check HTTPS
      const httpsResult = await httpCheck(targetHost, 443, true);
      if (httpsResult.alive) {
        result.status = HEALTH_STATUS.ALIVE;
        result.statusCode = httpsResult.statusCode;
        result.checkMethod = 'https';
        result.portsOpen.push(443);
        // Get SSL info
        const ssl = await getSSLInfo(targetHost);
        if (ssl) { result.sslValid = ssl.valid; result.sslExpiresAt = ssl.expires; result.sslError = ssl.error; }
      }

      // Check HTTP
      if (result.status !== HEALTH_STATUS.ALIVE) {
        const httpResult = await httpCheck(targetHost, 80, false);
        if (httpResult.alive) {
          result.status = HEALTH_STATUS.ALIVE;
          result.statusCode = httpResult.statusCode;
          result.checkMethod = 'http';
          result.portsOpen.push(80);
        }
      }

      // Check common TCP ports
      if (result.status !== HEALTH_STATUS.ALIVE) {
        for (const { port, name } of COMMON_PORTS) {
          if (result.portsOpen.includes(port)) continue;
          const open = await tcpCheck(targetIP, port);
          if (open) { result.portsOpen.push(port); result.status = HEALTH_STATUS.ALIVE; result.checkMethod = `tcp:${port}`; }
        }
      }

      // ICMP ping
      if (result.status !== HEALTH_STATUS.ALIVE) {
        const pingOk = await icmpPing(targetIP);
        if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
      }

      // If nothing responded
      if (result.status !== HEALTH_STATUS.ALIVE) {
        result.status = HEALTH_STATUS.DEAD;
        result.errorMessage = 'No response on any port or ICMP';
        result.checkMethod = 'all_failed';
      }

    } else if (record.record_type === 'MX') {
      for (const { port, name } of MX_PORTS) {
        let mxIP = record.value;
        try { const addrs = await dns.promises.resolve4(record.value); mxIP = addrs[0]; } catch (e) {}
        if (isPrivateIP(mxIP)) { result.status = HEALTH_STATUS.SKIPPED; result.errorMessage = 'Private IP'; break; }
        const open = await tcpCheck(mxIP, port);
        if (open) { result.portsOpen.push(port); result.status = HEALTH_STATUS.ALIVE; result.checkMethod = `tcp:${port}`; break; }
      }
      if (result.status !== HEALTH_STATUS.ALIVE && result.status !== HEALTH_STATUS.SKIPPED) {
        const mxIP = record.value;
        const pingOk = await icmpPing(mxIP);
        if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
        else { result.status = HEALTH_STATUS.DEAD; result.errorMessage = 'No MX ports responding'; result.checkMethod = 'all_failed'; }
      }

    } else if (record.record_type === 'NS') {
      // Resolve NS hostname to IP first
      let nsIP = record.value;
      try { const addrs = await dns.promises.resolve4(record.value); nsIP = addrs[0]; } catch (e) {}
      if (isPrivateIP(nsIP)) { result.status = HEALTH_STATUS.SKIPPED; result.errorMessage = 'Private IP'; }
      else {
        const nsOk = await dnsQueryCheck(nsIP);
        if (nsOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'dns_query'; }
        else {
          const pingOk = await icmpPing(nsIP);
          if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
          else { result.status = HEALTH_STATUS.DEAD; result.errorMessage = 'NS not responding'; result.checkMethod = 'all_failed'; }
        }
      }

    } else if (record.record_type === 'SRV') {
      const [host, portStr] = record.value.split(':');
      const port = parseInt(portStr);
      if (host && port) {
        let srvIP = host;
        try { const addrs = await dns.promises.resolve4(host); srvIP = addrs[0]; } catch (e) {}
        if (isPrivateIP(srvIP)) { result.status = HEALTH_STATUS.SKIPPED; result.errorMessage = 'Private IP'; }
        else {
          const open = await tcpCheck(srvIP, port);
          if (open) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = `tcp:${port}`; result.portsOpen.push(port); }
          else {
            const pingOk = await icmpPing(srvIP);
            if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
            else { result.status = HEALTH_STATUS.DEAD; result.errorMessage = 'SRV not responding'; result.checkMethod = 'all_failed'; }
          }
        }
      }
    }
  } catch (err) {
    result.status = HEALTH_STATUS.ERROR;
    result.errorMessage = err.message;
    result.checkMethod = 'error';
  }

  result.responseMs = Date.now() - startTime;
  return result;
}

async function performScan(domain, scanId) {
  const { broadcastSSE } = require('./server');
  console.log(`[SCANNER] Starting scan for ${domain.domain} (scan ${scanId})`);

  // Refresh configurable settings from DB at the start of each scan
  await refreshScannerSettings();
  const scanSemaphore = new Semaphore(_maxConcurrentChecks);

  try {
    // Step 1: Enumerate DNS records
    const dnsRecords = await enumerateDNS(domain.domain);
    console.log(`[SCANNER] Found ${dnsRecords.length} DNS records for ${domain.domain}`);

    // Step 2: Diff with stored records
    const existingRecords = await query(
      'SELECT * FROM dns_records WHERE domain_id = $1 AND removed_at IS NULL',
      [domain.id]
    );
    const existingMap = new Map();
    for (const r of existingRecords.rows) {
      existingMap.set(`${r.record_type}:${r.name}:${r.value}`, r);
    }

    const foundKeys = new Set();
    const recordsToCheck = [];

    for (const rec of dnsRecords) {
      const key = `${rec.type}:${rec.name}:${rec.value}`;
      foundKeys.add(key);

      if (existingMap.has(key)) {
        // Update last_seen
        const existing = existingMap.get(key);
        await query('UPDATE dns_records SET last_seen = NOW(), ttl = $1 WHERE id = $2', [rec.ttl || existing.ttl, existing.id]);
        recordsToCheck.push({ ...existing, ttl: rec.ttl || existing.ttl });
      } else {
        // Check if value changed for same type+name
        const changed = existingRecords.rows.find(r => r.record_type === rec.type && r.name === rec.name && r.value.toLowerCase().replace(/\.$/, '') !== rec.value.toLowerCase().replace(/\.$/, ''));
        if (changed) {
          await query(
            'INSERT INTO dns_changes (record_id, domain_id, record_type, name, old_value, new_value) VALUES ($1, $2, $3, $4, $5, $6)',
            [changed.id, domain.id, rec.type, rec.name, changed.value, rec.value]
          );
        }
        // New record
        const result = await query(
          'INSERT INTO dns_records (domain_id, record_type, name, value, priority, ttl) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (domain_id, record_type, name, value) DO UPDATE SET last_seen = NOW(), removed_at = NULL RETURNING *',
          [domain.id, rec.type, rec.name, rec.value, rec.priority || null, rec.ttl || null]
        );
        recordsToCheck.push(result.rows[0]);
      }
    }

    // Mark removed records
    for (const [key, existing] of existingMap) {
      if (!foundKeys.has(key)) {
        await query('UPDATE dns_records SET removed_at = NOW() WHERE id = $1', [existing.id]);
      }
    }

    // Step 3: Health check all records
    let alive = 0, dead = 0;
    const checkPromises = recordsToCheck.map(async (record) => {
      await scanSemaphore.acquire();
      try {
        const healthResult = await healthCheckRecord(record, domain.domain);

        // Takeover check for CNAME records
        if (record.record_type === 'CNAME') {
          const takeoverResult = await checkTakeover(record.value, domain.domain);
          if (takeoverResult.risk) {
            healthResult.status = HEALTH_STATUS.TAKEOVER_RISK;
            healthResult.errorMessage = `Takeover risk: ${takeoverResult.service} - ${takeoverResult.detail}`;
            await query('UPDATE dns_records SET takeover_risk = TRUE WHERE id = $1', [record.id]);
          }
        }

        // Propagation check
        const propagationResults = await checkPropagation(
          record.name === '@' ? domain.domain : `${record.name}.${domain.domain}`,
          record.record_type
        );

        // Store health check
        await query(
          `INSERT INTO health_checks (record_id, status, status_code, response_ms, error_message, check_method, ports_open, ssl_valid, ssl_expires_at, ssl_error, propagation_results)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [record.id, healthResult.status, healthResult.statusCode, healthResult.responseMs,
           healthResult.errorMessage, healthResult.checkMethod, JSON.stringify(healthResult.portsOpen),
           healthResult.sslValid, healthResult.sslExpiresAt, healthResult.sslError,
           propagationResults ? JSON.stringify(propagationResults) : null]
        );

        if (healthResult.status === HEALTH_STATUS.ALIVE) alive++;
        else if (healthResult.status === HEALTH_STATUS.DEAD || healthResult.status === HEALTH_STATUS.TAKEOVER_RISK) dead++;

        return healthResult;
      } finally {
        scanSemaphore.release();
      }
    });

    await Promise.all(checkPromises);

    // Step 4: Update scan record
    await query(
      'UPDATE scans SET completed_at = NOW(), status = $1, records_found = $2, records_alive = $3, records_dead = $4 WHERE id = $5',
      [SCAN_STATUS.COMPLETED, recordsToCheck.length, alive, dead, scanId]
    );

    console.log(`[SCANNER] Scan complete for ${domain.domain}: ${recordsToCheck.length} records, ${alive} alive, ${dead} dead`);

    // Step 5: Trigger notifications
    try {
      const { processPostScanNotifications } = require('./notifier');
      await processPostScanNotifications(domain, scanId);
    } catch (e) {
      console.error(`[SCANNER] Notification error: ${e.message}`);
    }

    broadcastSSE({ type: 'scan_completed', domainId: domain.id, scanId, alive, dead, total: recordsToCheck.length });

  } catch (err) {
    console.error(`[SCANNER] Scan failed for ${domain.domain}:`, err.message);
    await query('UPDATE scans SET completed_at = NOW(), status = $1 WHERE id = $2', [SCAN_STATUS.FAILED, scanId]);
    broadcastSSE({ type: 'scan_failed', domainId: domain.id, scanId, error: err.message });
  }
}

module.exports = { performScan, enumerateDNS, healthCheckRecord, checkIPv6Connectivity, hasIPv6 };
