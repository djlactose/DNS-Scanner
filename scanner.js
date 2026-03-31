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
  COMMON_PORTS, MX_PORTS, FULL_SCAN_PORTS, PRIVATE_RANGES_V4, COMMON_SUBDOMAINS,
} = require('./constants');
const { getSetting } = require('./settings-service');
const { fetchProviderRecords } = require('./dns-providers');

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

function execDig(args, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(''), timeoutMs);
    try {
      execFile('dig', args, { timeout: timeoutMs }, (err, stdout) => {
        clearTimeout(timeout);
        resolve(err ? '' : (stdout || ''));
      });
    } catch (e) { clearTimeout(timeout); resolve(''); }
  });
}

function parseDigRecords(stdout, domain) {
  const records = [];
  const lines = stdout.trim().split('\n').filter(l => l && !l.startsWith(';'));
  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length >= 5) {
      let name = parts[0].replace(/\.$/, '');
      const type = parts[3];
      let value = parts.slice(4).join(' ').replace(/\.$/, '');
      if (!RECORD_TYPES.includes(type) || !value) continue;
      // Convert FQDN name to relative
      if (name === domain) name = '@';
      else if (name.endsWith('.' + domain)) name = name.slice(0, -(domain.length + 1));
      const priority = type === 'MX' ? parseInt(parts[4]) : null;
      if (type === 'MX') value = parts.slice(5).join(' ').replace(/\.$/, '');
      records.push({ name, type, value, ttl: parseInt(parts[1]) || null, priority });
    }
  }
  return records;
}

async function attemptAXFR(domain) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve([]), 15000);
    try {
      dns.resolveNs(domain, async (err, nsRecords) => {
        if (err || !nsRecords?.length) { clearTimeout(timeout); return resolve([]); }
        // Try AXFR against each NS until one works
        for (const ns of nsRecords) {
          const stdout = await execDig(['@' + ns, domain, 'AXFR', '+time=10'], 15000);
          if (stdout && !stdout.includes('Transfer failed') && !stdout.includes('; Transfer failed')) {
            const records = parseDigRecords(stdout, domain);
            if (records.length > 0) { clearTimeout(timeout); return resolve(records); }
          }
        }
        clearTimeout(timeout);
        resolve([]);
      });
    } catch (e) { clearTimeout(timeout); resolve([]); }
  });
}

async function attemptNSECWalk(domain) {
  const records = [];
  const seen = new Set();
  let current = domain;
  const maxSteps = 500;

  for (let i = 0; i < maxSteps; i++) {
    const stdout = await execDig(['@8.8.8.8', current, 'NSEC', '+dnssec', '+time=5'], 10000);
    if (!stdout) break;

    // Extract NSEC record to find next domain name
    const nsecLine = stdout.split('\n').find(l => !l.startsWith(';') && l.includes('\tNSEC\t'));
    if (!nsecLine) break;

    const parts = nsecLine.split(/\s+/);
    const nsecIdx = parts.indexOf('NSEC');
    if (nsecIdx < 0 || nsecIdx + 1 >= parts.length) break;

    const nextName = parts[nsecIdx + 1].replace(/\.$/, '');
    // Types listed after the next name are the types that exist at 'current'
    const existingTypes = parts.slice(nsecIdx + 2);

    // Record the current name's types
    const currentClean = current.replace(/\.$/, '');
    if (!seen.has(currentClean)) {
      seen.add(currentClean);
      let name = currentClean === domain ? '@' : currentClean.endsWith('.' + domain) ? currentClean.slice(0, -(domain.length + 1)) : currentClean;
      for (const type of existingTypes) {
        if (RECORD_TYPES.includes(type)) {
          records.push({ name, type, _needsResolve: true });
        }
      }
    }

    // Move to next name in the chain
    if (nextName === domain || nextName === current || seen.has(nextName)) break;
    if (!nextName.endsWith('.' + domain) && nextName !== domain) break;
    current = nextName;
  }

  return records;
}

async function enumerateDNS(domain) {
  const records = [];
  const resolver = new dns.promises.Resolver();
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  // ─── DNS provider APIs (Cloudflare, Route 53, DigitalOcean, GoDaddy) ───
  let providerResult = { records: [], authoritative: false, providers: [] };
  try {
    providerResult = await fetchProviderRecords(domain);
    if (providerResult.records.length > 0) {
      console.log(`[SCANNER] DNS providers returned ${providerResult.records.length} records for ${domain} (authoritative: ${providerResult.authoritative}, providers: ${providerResult.providers.join(', ')})`);
    }
  } catch (e) {
    console.log(`[SCANNER] DNS provider fetch error for ${domain}: ${e.message}`);
  }

  // When a provider is authoritative, use only its records as the source of truth
  if (providerResult.authoritative) {
    const seen = new Set();
    const deduped = providerResult.records.filter(r => {
      const key = `${r.type}:${r.name}:${r.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    console.log(`[SCANNER] Provider-authoritative mode for ${domain}: ${deduped.length} records from ${providerResult.providers.join(', ')}`);
    return { records: deduped, authoritative: true, providers: providerResult.providers };
  }

  records.push(...providerResult.records);

  // Try AXFR zone transfer
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
          results = await resolver.resolve4(domain);
          for (const ip of results) records.push({ name: '@', type: 'A', value: ip });
          break;
        case 'AAAA':
          results = await resolver.resolve6(domain);
          for (const ip of results) records.push({ name: '@', type: 'AAAA', value: ip });
          break;
        case 'CNAME':
          try {
            results = await resolver.resolveCname(domain);
            for (const cname of results) records.push({ name: '@', type: 'CNAME', value: cname });
          } catch (e) { /* CNAME often doesn't exist at apex */ }
          break;
        case 'MX':
          results = await resolver.resolveMx(domain);
          for (const mx of results) {
            if (mx.exchange) records.push({ name: '@', type: 'MX', value: mx.exchange, priority: mx.priority });
          }
          break;
        case 'TXT':
          results = await resolver.resolveTxt(domain);
          for (const txt of results) records.push({ name: '@', type: 'TXT', value: txt.join('') });
          break;
        case 'NS':
          results = await resolver.resolveNs(domain);
          for (const ns of results) records.push({ name: '@', type: 'NS', value: ns });
          break;
        case 'SRV':
          try {
            results = await resolver.resolveSrv(domain);
            for (const srv of results) records.push({ name: '@', type: 'SRV', value: `${srv.name}:${srv.port}`, priority: srv.priority });
          } catch (e) { /* SRV often doesn't exist */ }
          break;
        case 'CAA':
          try {
            results = await resolver.resolveCaa(domain);
            for (const caa of results) records.push({ name: '@', type: 'CAA', value: `${caa.critical} ${caa.issue || caa.issuewild || caa.iodef || ''}` });
          } catch (e) { /* CAA often doesn't exist */ }
          break;
        case 'SOA':
          try {
            results = await resolver.resolveSoa(domain);
            if (results) records.push({ name: '@', type: 'SOA', value: `${results.nsname} ${results.hostmaster}` });
          } catch (e) {}
          break;
      }
    } catch (e) {
      // Record type doesn't exist for this domain
    }
  }

  console.log(`[SCANNER] Apex enumeration for ${domain}: ${records.length} records (${records.map(r => r.type).filter((v, i, a) => a.indexOf(v) === i).join(', ')})`);

  // ─── NSEC walking (DNSSEC-signed domains) ───
  let nsecNames = [];
  try {
    const nsecRecords = await attemptNSECWalk(domain);
    if (nsecRecords.length > 0) {
      // NSEC tells us which names and types exist — resolve the actual values
      const nsecSubs = new Set();
      for (const r of nsecRecords) {
        if (r.name !== '@') nsecSubs.add(r.name);
      }
      nsecNames = [...nsecSubs];
      console.log(`[SCANNER] NSEC walk for ${domain}: discovered ${nsecNames.length} subdomains`);
    }
  } catch (e) {
    console.log(`[SCANNER] NSEC walk failed for ${domain}: ${e.message}`);
  }

  // ─── Certificate Transparency logs ───
  let ctSubdomains = [];
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: controller.signal });
    clearTimeout(timeout);
    if (res.ok) {
      const certs = await res.json();
      const subSet = new Set();
      for (const cert of certs) {
        const names = (cert.name_value || '').split('\n');
        for (const name of names) {
          const clean = name.trim().toLowerCase().replace(/^\*\./, '');
          if (clean.endsWith(`.${domain}`) && !clean.includes('*')) {
            const sub = clean.slice(0, -(domain.length + 1));
            if (sub) subSet.add(sub);
          }
        }
      }
      ctSubdomains = [...subSet];
      console.log(`[SCANNER] CT logs for ${domain}: found ${ctSubdomains.length} unique subdomains`);
    }
  } catch (e) {
    console.log(`[SCANNER] CT log lookup failed for ${domain}: ${e.message}`);
  }

  // ─── Merge all subdomain sources (deduplicated) ───
  const allSubdomains = [...new Set([...COMMON_SUBDOMAINS, ...ctSubdomains, ...nsecNames])];
  console.log(`[SCANNER] Total subdomains to check for ${domain}: ${allSubdomains.length}`);

  // ─── Resolve all subdomains for all applicable record types ───
  async function resolveSubdomain(sub) {
    const fqdn = `${sub}.${domain}`;
    const subRecords = [];

    // CNAME check first
    try {
      const cnames = await resolver.resolveCname(fqdn);
      for (const cname of cnames) subRecords.push({ name: sub, type: 'CNAME', value: cname });
    } catch (e) { /* no CNAME */ }

    // A/AAAA (only if no CNAME — they're mutually exclusive)
    if (!subRecords.some(r => r.type === 'CNAME')) {
      try {
        const ips = await resolver.resolve4(fqdn);
        for (const ip of ips) subRecords.push({ name: sub, type: 'A', value: ip });
      } catch (e) {}
      try {
        const ips = await resolver.resolve6(fqdn);
        for (const ip of ips) subRecords.push({ name: sub, type: 'AAAA', value: ip });
      } catch (e) {}
    }

    // TXT records on all subdomains (SPF, DKIM, DMARC, verification records, etc.)
    try {
      const txts = await resolver.resolveTxt(fqdn);
      for (const txt of txts) subRecords.push({ name: sub, type: 'TXT', value: txt.join('') });
    } catch (e) {}

    // MX on subdomains (some orgs have mail on subdomains)
    try {
      const mxes = await resolver.resolveMx(fqdn);
      for (const mx of mxes) {
        if (mx.exchange) subRecords.push({ name: sub, type: 'MX', value: mx.exchange, priority: mx.priority });
      }
    } catch (e) {}

    // SRV on underscore-prefixed subdomains
    if (sub.startsWith('_')) {
      try {
        const srvs = await resolver.resolveSrv(fqdn);
        for (const srv of srvs) subRecords.push({ name: sub, type: 'SRV', value: `${srv.name}:${srv.port}`, priority: srv.priority });
      } catch (e) {}
    }

    return subRecords;
  }

  // Run in batches to avoid overwhelming DNS resolvers
  const BATCH_SIZE = 50;
  let subCount = 0;
  for (let i = 0; i < allSubdomains.length; i += BATCH_SIZE) {
    const batch = allSubdomains.slice(i, i + BATCH_SIZE);
    const results = await Promise.allSettled(batch.map(resolveSubdomain));
    for (const result of results) {
      if (result.status === 'fulfilled') { subCount += result.value.length; records.push(...result.value); }
    }
  }
  console.log(`[SCANNER] Subdomain enumeration for ${domain}: ${subCount} additional records from ${allSubdomains.length} subdomains`);

  // Deduplicate
  const seen = new Set();
  const deduped = records.filter(r => {
    const key = `${r.type}:${r.name}:${r.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { records: deduped, authoritative: false, providers: [] };
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

async function fullPortScan(host, timeoutMs = 3000) {
  const openPorts = [];
  // Scan in batches of 20 to avoid too many concurrent connections
  for (let i = 0; i < FULL_SCAN_PORTS.length; i += 20) {
    const batch = FULL_SCAN_PORTS.slice(i, i + 20);
    const results = await Promise.allSettled(
      batch.map(async ({ port, name }) => {
        const open = await tcpCheck(host, port, timeoutMs);
        return open ? { port, name } : null;
      })
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) openPorts.push(r.value);
    }
  }
  return openPorts;
}

async function healthCheckRecord(record, domain) {
  const startTime = Date.now();
  const needsPortScan = !record.last_port_scan || record._forcePortScan;
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
    // ─── Custom health check port override ───
    if (record.health_check_port) {
      const port = record.health_check_port;
      const open = await tcpCheck(targetHost, port);
      if (open) {
        result.status = HEALTH_STATUS.ALIVE;
        result.checkMethod = `tcp:${port}`;
        result.portsOpen = [port];
        // Collect SSL info if checking port 443
        if (port === 443) {
          const ssl = await getSSLInfo(targetHost);
          if (ssl) { result.sslValid = ssl.valid; result.sslExpiresAt = ssl.expires; result.sslError = ssl.error; }
        }
      } else {
        result.status = HEALTH_STATUS.DEAD;
        result.errorMessage = `Custom health check port ${port} is not responding`;
        result.checkMethod = `tcp:${port}`;
      }
      result.responseMs = Date.now() - startTime;
      return result;
    }

    if (record.record_type === 'A' || record.record_type === 'AAAA' || record.record_type === 'CNAME') {

      if (needsPortScan) {
        // ─── Full port scan (first discovery or manual rescan) ───
        const discovered = await fullPortScan(targetHost);
        result.portsOpen = discovered.map(p => p.port);
        result._knownPorts = discovered; // pass to caller for DB storage

        // Check HTTPS specifically for SSL info
        if (result.portsOpen.includes(443)) {
          const httpsResult = await httpCheck(targetHost, 443, true);
          if (httpsResult.alive) { result.statusCode = httpsResult.statusCode; result.checkMethod = 'https'; }
          const ssl = await getSSLInfo(targetHost);
          if (ssl) { result.sslValid = ssl.valid; result.sslExpiresAt = ssl.expires; result.sslError = ssl.error; }
        } else if (result.portsOpen.includes(80)) {
          const httpResult = await httpCheck(targetHost, 80, false);
          if (httpResult.alive) { result.statusCode = httpResult.statusCode; result.checkMethod = 'http'; }
        }

        if (result.portsOpen.length > 0) {
          result.status = HEALTH_STATUS.ALIVE;
          if (!result.checkMethod) result.checkMethod = `tcp:${result.portsOpen[0]}`;
        } else {
          const pingOk = await icmpPing(targetHost);
          if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
        }

      } else {
        // ─── Quick check: only check previously known ports ───
        const knownPorts = (record.known_ports || []);

        // Always check HTTPS/HTTP first for status code + SSL
        if (knownPorts.includes(443)) {
          const httpsResult = await httpCheck(targetHost, 443, true);
          if (httpsResult.alive) {
            result.status = HEALTH_STATUS.ALIVE;
            result.statusCode = httpsResult.statusCode;
            result.checkMethod = 'https';
            result.portsOpen.push(443);
          }
          const ssl = await getSSLInfo(targetHost);
          if (ssl) { result.sslValid = ssl.valid; result.sslExpiresAt = ssl.expires; result.sslError = ssl.error; }
        }
        if (result.status !== HEALTH_STATUS.ALIVE && knownPorts.includes(80)) {
          const httpResult = await httpCheck(targetHost, 80, false);
          if (httpResult.alive) {
            result.status = HEALTH_STATUS.ALIVE;
            result.statusCode = httpResult.statusCode;
            result.checkMethod = 'http';
            result.portsOpen.push(80);
          }
        }

        // Check remaining known ports
        for (const port of knownPorts) {
          if (port === 443 || port === 80) continue;
          const open = await tcpCheck(targetHost, port);
          if (open) { result.portsOpen.push(port); if (result.status !== HEALTH_STATUS.ALIVE) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = `tcp:${port}`; } }
        }

        // If no known ports, fall back to common ports check
        if (knownPorts.length === 0) {
          for (const { port } of COMMON_PORTS) {
            const open = await tcpCheck(targetHost, port);
            if (open) { result.portsOpen.push(port); result.status = HEALTH_STATUS.ALIVE; result.checkMethod = `tcp:${port}`; break; }
          }
        }

        // ICMP ping fallback
        if (result.status !== HEALTH_STATUS.ALIVE) {
          const pingOk = await icmpPing(targetHost);
          if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
        }
      }

      // If nothing responded
      if (result.status !== HEALTH_STATUS.ALIVE) {
        result.status = HEALTH_STATUS.DEAD;
        result.errorMessage = 'No response on any port or ICMP';
        result.checkMethod = 'all_failed';
      }

    } else if (record.record_type === 'MX') {
      const mxHost = record.value;
      let mxIP = mxHost;
      try { const addrs = await dns.promises.resolve4(mxHost); mxIP = addrs[0]; } catch (e) {}
      if (isPrivateIP(mxIP)) { result.status = HEALTH_STATUS.SKIPPED; result.errorMessage = 'Private IP'; }
      else {
        for (const { port, name } of MX_PORTS) {
          const open = await tcpCheck(mxHost, port);
          if (open) { result.portsOpen.push(port); result.status = HEALTH_STATUS.ALIVE; result.checkMethod = `tcp:${port}`; break; }
        }
        if (result.status !== HEALTH_STATUS.ALIVE) {
          const pingOk = await icmpPing(mxHost);
          if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
          else { result.status = HEALTH_STATUS.DEAD; result.errorMessage = 'No MX ports responding'; result.checkMethod = 'all_failed'; }
        }
      }

    } else if (record.record_type === 'NS') {
      const nsHost = record.value;
      let nsIP = nsHost;
      try { const addrs = await dns.promises.resolve4(nsHost); nsIP = addrs[0]; } catch (e) {}
      if (isPrivateIP(nsIP)) { result.status = HEALTH_STATUS.SKIPPED; result.errorMessage = 'Private IP'; }
      else {
        const nsOk = await dnsQueryCheck(nsIP);
        if (nsOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'dns_query'; }
        else {
          const pingOk = await icmpPing(nsHost);
          if (pingOk) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = 'icmp'; }
          else { result.status = HEALTH_STATUS.DEAD; result.errorMessage = 'NS not responding'; result.checkMethod = 'all_failed'; }
        }
      }

    } else if (record.record_type === 'SRV') {
      const [srvHost, portStr] = record.value.split(':');
      const port = parseInt(portStr);
      if (srvHost && port) {
        let srvIP = srvHost;
        try { const addrs = await dns.promises.resolve4(srvHost); srvIP = addrs[0]; } catch (e) {}
        if (isPrivateIP(srvIP)) { result.status = HEALTH_STATUS.SKIPPED; result.errorMessage = 'Private IP'; }
        else {
          const open = await tcpCheck(srvHost, port);
          if (open) { result.status = HEALTH_STATUS.ALIVE; result.checkMethod = `tcp:${port}`; result.portsOpen.push(port); }
          else {
            const pingOk = await icmpPing(srvHost);
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
    const enumResult = await enumerateDNS(domain.domain);
    const dnsRecords = enumResult.records;
    console.log(`[SCANNER] Found ${dnsRecords.length} DNS records for ${domain.domain} (authoritative: ${enumResult.authoritative})`);

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
    let alive = 0, dead = 0, checked = 0;
    const totalToCheck = recordsToCheck.length;
    broadcastSSE({ type: 'scan_progress', domainId: domain.id, scanId, phase: 'enumerating', checked: 0, total: totalToCheck });

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

        // Store discovered ports from full port scan
        if (healthResult._knownPorts) {
          await query(
            'UPDATE dns_records SET known_ports = $1, last_port_scan = NOW() WHERE id = $2',
            [JSON.stringify(healthResult.portsOpen), record.id]
          );
        }

        if (healthResult.status === HEALTH_STATUS.ALIVE) alive++;
        else if (healthResult.status === HEALTH_STATUS.DEAD || healthResult.status === HEALTH_STATUS.TAKEOVER_RISK) dead++;

        checked++;
        broadcastSSE({ type: 'scan_progress', domainId: domain.id, scanId, phase: 'checking', checked, total: totalToCheck, alive, dead });

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

async function portScanRecord(recordId) {
  const result = await query('SELECT dr.*, d.domain FROM dns_records dr JOIN domains d ON d.id = dr.domain_id WHERE dr.id = $1', [recordId]);
  if (!result.rows.length) throw new Error('Record not found');
  const record = result.rows[0];
  record._forcePortScan = true;
  const healthResult = await healthCheckRecord(record, record.domain);
  if (healthResult._knownPorts) {
    await query('UPDATE dns_records SET known_ports = $1, last_port_scan = NOW() WHERE id = $2',
      [JSON.stringify(healthResult.portsOpen), recordId]);
  }
  return { portsOpen: healthResult.portsOpen, status: healthResult.status };
}

module.exports = { performScan, enumerateDNS, healthCheckRecord, fullPortScan, portScanRecord, tcpCheck, checkIPv6Connectivity, hasIPv6 };
