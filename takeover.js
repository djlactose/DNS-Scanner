'use strict';

const { TAKEOVER_FINGERPRINTS } = require('./constants');

async function checkTakeover(cnameTarget, domain) {
  const target = cnameTarget.toLowerCase();

  for (const fp of TAKEOVER_FINGERPRINTS) {
    if (!target.includes(fp.cname.toLowerCase())) continue;

    // Matched a known service pattern — check if unclaimed
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      const response = await fetch(`http://${cnameTarget}`, {
        signal: controller.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'DNS-Scanner/1.0', 'Host': domain },
      });
      clearTimeout(timer);
      const body = await response.text();

      if (body.includes(fp.fingerprint)) {
        return { risk: true, service: fp.service, detail: fp.fingerprint };
      }
    } catch (e) {
      // Also try HTTPS
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);
        const response = await fetch(`https://${cnameTarget}`, {
          signal: controller.signal,
          redirect: 'follow',
          headers: { 'User-Agent': 'DNS-Scanner/1.0' },
        });
        clearTimeout(timer);
        const body = await response.text();

        if (body.includes(fp.fingerprint)) {
          return { risk: true, service: fp.service, detail: fp.fingerprint };
        }
      } catch (e2) {
        // If both fail, the CNAME target may be down — could be vulnerable
        // But we don't flag unless we see the fingerprint
      }
    }
  }

  return { risk: false };
}

module.exports = { checkTakeover };
