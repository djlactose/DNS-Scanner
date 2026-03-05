'use strict';

const dns = require('node:dns');
const { PUBLIC_RESOLVERS } = require('./constants');

async function resolveWithServer(name, type, serverIP) {
  return new Promise((resolve) => {
    const resolver = new dns.Resolver();
    resolver.setServers([serverIP]);
    const timeout = setTimeout(() => resolve({ server: serverIP, error: 'timeout', values: [] }), 8000);

    const callback = (err, result) => {
      clearTimeout(timeout);
      if (err) return resolve({ server: serverIP, error: err.code, values: [] });

      let values = [];
      if (Array.isArray(result)) {
        values = result.map(r => {
          if (typeof r === 'string') return r;
          if (r.exchange) return `${r.priority} ${r.exchange}`;
          if (Array.isArray(r)) return r.join('');
          return JSON.stringify(r);
        });
      } else if (result) {
        values = [typeof result === 'string' ? result : JSON.stringify(result)];
      }

      resolve({ server: serverIP, values: values.sort() });
    };

    try {
      switch (type) {
        case 'A': resolver.resolve4(name, callback); break;
        case 'AAAA': resolver.resolve6(name, callback); break;
        case 'CNAME': resolver.resolveCname(name, callback); break;
        case 'MX': resolver.resolveMx(name, callback); break;
        case 'TXT': resolver.resolveTxt(name, callback); break;
        case 'NS': resolver.resolveNs(name, callback); break;
        default: clearTimeout(timeout); resolve({ server: serverIP, values: [], error: 'unsupported_type' });
      }
    } catch (e) {
      clearTimeout(timeout);
      resolve({ server: serverIP, error: e.message, values: [] });
    }
  });
}

async function checkPropagation(name, type) {
  if (['CAA', 'SOA', 'SRV'].includes(type)) return null;

  const results = await Promise.all(
    PUBLIC_RESOLVERS.map(r => resolveWithServer(name, type, r.ip).then(res => ({ ...res, name: r.name })))
  );

  // Check consistency
  const validResults = results.filter(r => !r.error && r.values.length > 0);
  let consistent = true;

  if (validResults.length > 1) {
    const reference = JSON.stringify(validResults[0].values);
    for (let i = 1; i < validResults.length; i++) {
      if (JSON.stringify(validResults[i].values) !== reference) {
        consistent = false;
        break;
      }
    }
  }

  return {
    consistent,
    resolvers: results.map(r => ({
      name: r.name,
      server: r.server,
      values: r.values,
      error: r.error || null,
    })),
  };
}

module.exports = { checkPropagation };
