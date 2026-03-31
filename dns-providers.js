'use strict';

const { getSetting } = require('./settings-service');
const { RECORD_TYPES } = require('./constants');

// ─── Cloudflare ───

async function fetchCloudflareRecords(domain) {
  const token = await getSetting('cloudflare_api_token');
  if (!token) return { records: [], zoneFound: false };

  try {
    // Find zone ID for this domain
    const zoneRes = await fetch(`https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(domain)}&per_page=1`, {
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    });
    const zoneData = await zoneRes.json();
    if (!zoneData.success || !zoneData.result?.length) return { records: [], zoneFound: false };

    const zoneId = zoneData.result[0].id;

    // Fetch all DNS records (paginated)
    const records = [];
    let page = 1;
    while (true) {
      const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?per_page=5000&page=${page}`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!data.success) break;

      for (const r of data.result) {
        const type = r.type;
        if (!RECORD_TYPES.includes(type)) continue;

        let name = r.name;
        if (name === domain) name = '@';
        else if (name.endsWith('.' + domain)) name = name.slice(0, -(domain.length + 1));

        let value = r.content;
        const priority = r.priority || null;

        records.push({ name, type, value, ttl: r.ttl || null, priority });
      }

      if (page >= data.result_info.total_pages) break;
      page++;
    }

    console.log(`[PROVIDER] Cloudflare: ${records.length} records for ${domain}`);
    return { records, zoneFound: true };
  } catch (e) {
    console.log(`[PROVIDER] Cloudflare failed for ${domain}: ${e.message}`);
    return { records: [], zoneFound: false };
  }
}

// ─── AWS Route 53 ───

function hmacSHA256(key, data) {
  const crypto = require('node:crypto');
  return crypto.createHmac('sha256', key).update(data).digest();
}

function sha256(data) {
  const crypto = require('node:crypto');
  return crypto.createHash('sha256').update(data).digest('hex');
}

function getRoute53SignatureHeaders(accessKey, secretKey, region, service, method, path, body = '') {
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  const dateOnly = dateStamp.slice(0, 8);
  const host = `${service}.${region}.amazonaws.com`;

  const canonicalHeaders = `host:${host}\nx-amz-date:${dateStamp}\n`;
  const signedHeaders = 'host;x-amz-date';
  const payloadHash = sha256(body);
  const canonicalRequest = `${method}\n${path}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

  const credentialScope = `${dateOnly}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${dateStamp}\n${credentialScope}\n${sha256(canonicalRequest)}`;

  let signingKey = Buffer.from('AWS4' + secretKey);
  for (const part of [dateOnly, region, service, 'aws4_request']) {
    signingKey = hmacSHA256(signingKey, part);
  }
  const signature = hmacSHA256(signingKey, stringToSign).toString('hex');

  return {
    'Host': host,
    'X-Amz-Date': dateStamp,
    'Authorization': `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

async function fetchRoute53Records(domain) {
  const accessKey = await getSetting('route53_access_key');
  const secretKey = await getSetting('route53_secret_key');
  if (!accessKey || !secretKey) return { records: [], zoneFound: false };

  try {
    const region = 'us-east-1';

    // List hosted zones to find the zone for this domain
    const listPath = '/2013-04-01/hostedzonesbyname?dnsname=' + encodeURIComponent(domain) + '&maxitems=1';
    const listHeaders = getRoute53SignatureHeaders(accessKey, secretKey, region, 'route53', 'GET', listPath);
    const listRes = await fetch(`https://route53.us-east-1.amazonaws.com${listPath}`, { headers: listHeaders });
    const listText = await listRes.text();

    // Parse XML to find hosted zone ID
    const zoneIdMatch = listText.match(/<HostedZone>.*?<Id>\/hostedzone\/(.*?)<\/Id>.*?<Name>(.*?)<\/Name>/s);
    if (!zoneIdMatch || !zoneIdMatch[2].replace(/\.$/, '').endsWith(domain)) return { records: [], zoneFound: false };
    const zoneId = zoneIdMatch[1];

    // List all record sets
    const records = [];
    let startName = '';
    let startType = '';

    while (true) {
      let rrPath = `/2013-04-01/hostedzone/${zoneId}/rrset?maxitems=300`;
      if (startName) rrPath += `&name=${encodeURIComponent(startName)}&type=${startType}`;

      const rrHeaders = getRoute53SignatureHeaders(accessKey, secretKey, region, 'route53', 'GET', rrPath);
      const rrRes = await fetch(`https://route53.us-east-1.amazonaws.com${rrPath}`, { headers: rrHeaders });
      const rrText = await rrRes.text();

      // Parse resource record sets from XML
      const rrSets = rrText.match(/<ResourceRecordSet>[\s\S]*?<\/ResourceRecordSet>/g) || [];
      for (const rrSet of rrSets) {
        const typeMatch = rrSet.match(/<Type>(.*?)<\/Type>/);
        const nameMatch = rrSet.match(/<Name>(.*?)<\/Name>/);
        if (!typeMatch || !nameMatch) continue;

        const type = typeMatch[1];
        if (!RECORD_TYPES.includes(type)) continue;

        let name = nameMatch[1].replace(/\.$/, '');
        if (name === domain) name = '@';
        else if (name.endsWith('.' + domain)) name = name.slice(0, -(domain.length + 1));

        const values = rrSet.match(/<Value>(.*?)<\/Value>/g) || [];
        for (const valMatch of values) {
          const value = valMatch.replace(/<\/?Value>/g, '').replace(/\.$/, '');
          const priority = type === 'MX' ? parseInt(value.split(/\s+/)[0]) : null;
          const cleanValue = type === 'MX' ? value.split(/\s+/).slice(1).join(' ') : value;
          records.push({ name, type, value: cleanValue, priority });
        }
      }

      // Check for pagination
      const isTruncated = rrText.includes('<IsTruncated>true</IsTruncated>');
      if (!isTruncated) break;
      const nextName = rrText.match(/<NextRecordName>(.*?)<\/NextRecordName>/);
      const nextType = rrText.match(/<NextRecordType>(.*?)<\/NextRecordType>/);
      if (!nextName || !nextType) break;
      startName = nextName[1];
      startType = nextType[1];
    }

    console.log(`[PROVIDER] Route 53: ${records.length} records for ${domain}`);
    return { records, zoneFound: true };
  } catch (e) {
    console.log(`[PROVIDER] Route 53 failed for ${domain}: ${e.message}`);
    return { records: [], zoneFound: false };
  }
}

// ─── DigitalOcean ───

async function fetchDigitalOceanRecords(domain) {
  const token = await getSetting('digitalocean_api_token');
  if (!token) return { records: [], zoneFound: false };

  try {
    const records = [];
    let page = 1;
    while (true) {
      const res = await fetch(`https://api.digitalocean.com/v2/domains/${encodeURIComponent(domain)}/records?per_page=200&page=${page}`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      });
      if (!res.ok) return { records: [], zoneFound: false };
      const data = await res.json();

      for (const r of data.domain_records) {
        const type = r.type;
        if (!RECORD_TYPES.includes(type)) continue;

        let name = r.name;
        if (name === '@') { /* keep as-is */ }
        else if (name === domain) name = '@';

        records.push({ name, type, value: r.data, ttl: r.ttl || null, priority: r.priority || null });
      }

      if (!data.links?.pages?.next) break;
      page++;
    }

    console.log(`[PROVIDER] DigitalOcean: ${records.length} records for ${domain}`);
    return { records, zoneFound: true };
  } catch (e) {
    console.log(`[PROVIDER] DigitalOcean failed for ${domain}: ${e.message}`);
    return { records: [], zoneFound: false };
  }
}

// ─── GoDaddy ───

async function fetchGoDaddyRecords(domain) {
  const apiKey = await getSetting('godaddy_api_key');
  const apiSecret = await getSetting('godaddy_api_secret');
  if (!apiKey || !apiSecret) return { records: [], zoneFound: false };

  try {
    const res = await fetch(`https://api.godaddy.com/v1/domains/${encodeURIComponent(domain)}/records`, {
      headers: { 'Authorization': `sso-key ${apiKey}:${apiSecret}`, 'Content-Type': 'application/json' },
    });
    if (!res.ok) return { records: [], zoneFound: false };
    const data = await res.json();

    const records = [];
    for (const r of data) {
      const type = r.type;
      if (!RECORD_TYPES.includes(type)) continue;

      let name = r.name;
      if (name === '@') { /* keep as-is */ }
      else if (name === domain) name = '@';

      records.push({ name, type, value: r.data, ttl: r.ttl || null, priority: r.priority || null });
    }

    console.log(`[PROVIDER] GoDaddy: ${records.length} records for ${domain}`);
    return { records, zoneFound: true };
  } catch (e) {
    console.log(`[PROVIDER] GoDaddy failed for ${domain}: ${e.message}`);
    return { records: [], zoneFound: false };
  }
}

// ─── Main entry point ───

async function fetchProviderRecords(domain) {
  const results = await Promise.allSettled([
    fetchCloudflareRecords(domain),
    fetchRoute53Records(domain),
    fetchDigitalOceanRecords(domain),
    fetchGoDaddyRecords(domain),
  ]);

  const NAMES = ['cloudflare', 'route53', 'digitalocean', 'godaddy'];
  const allRecords = [];
  const providers = [];

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (result.status === 'fulfilled' && result.value.zoneFound) {
      providers.push(NAMES[i]);
      allRecords.push(...result.value.records);
    }
  }

  return {
    records: allRecords,
    authoritative: providers.length > 0 && allRecords.length > 0,
    providers,
  };
}

module.exports = { fetchProviderRecords, fetchCloudflareRecords, fetchRoute53Records, fetchDigitalOceanRecords, fetchGoDaddyRecords };
