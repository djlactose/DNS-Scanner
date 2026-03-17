'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const BASE_URL = process.env.TEST_URL || 'http://localhost:8080';
let adminCookie = '';
let viewerCookie = '';
let adminUserId = null;
let testDomainId = null;

function request(method, path, body, cookie) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const opts = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        'Origin': BASE_URL,
      },
    };
    if (cookie) opts.headers['Cookie'] = cookie;

    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json;
        try { json = JSON.parse(data); } catch (e) { json = data; }
        const setCookie = res.headers['set-cookie'];
        resolve({ status: res.statusCode, body: json, cookie: setCookie ? setCookie[0].split(';')[0] : null });
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

describe('Health Check', () => {
  it('should return ok status', async () => {
    const res = await request('GET', '/health');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'ok');
    assert.strictEqual(res.body.db, 'ok');
    assert.ok(res.body.uptime >= 0);
    assert.ok(res.body.responseMs >= 0);
  });
});

describe('Auth API', () => {
  it('should register first user as admin', async () => {
    const res = await request('POST', '/api/auth/register', {
      username: 'testadmin',
      password: 'testpassword123',
      email: 'admin@test.com',
    });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.role, 'admin');
    assert.strictEqual(res.body.username, 'testadmin');
    adminCookie = res.cookie;
    adminUserId = res.body.id;
  });

  it('should get current user', async () => {
    const res = await request('GET', '/api/auth/me', null, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.username, 'testadmin');
    assert.strictEqual(res.body.role, 'admin');
  });

  it('should reject duplicate username', async () => {
    const res = await request('POST', '/api/auth/register', {
      username: 'testadmin',
      password: 'testpassword123',
    });
    assert.strictEqual(res.status, 409);
  });

  it('should register second user as viewer', async () => {
    const res = await request('POST', '/api/auth/register', {
      username: 'testviewer',
      password: 'viewerpassword123',
      email: 'viewer@test.com',
    });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.role, 'viewer');
    viewerCookie = res.cookie;
  });

  it('should login with valid credentials', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: 'testadmin',
      password: 'testpassword123',
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.username, 'testadmin');
    adminCookie = res.cookie || adminCookie;
  });

  it('should reject invalid credentials', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: 'testadmin',
      password: 'wrongpassword',
    });
    assert.strictEqual(res.status, 401);
  });

  it('should reject unauthenticated requests', async () => {
    const res = await request('GET', '/api/auth/me');
    assert.strictEqual(res.status, 401);
  });

  it('should change password', async () => {
    const res = await request('PUT', '/api/auth/password', {
      currentPassword: 'testpassword123',
      newPassword: 'newpassword123',
    }, adminCookie);
    assert.strictEqual(res.status, 200);
    // Login with new password
    const loginRes = await request('POST', '/api/auth/login', {
      username: 'testadmin',
      password: 'newpassword123',
    });
    assert.strictEqual(loginRes.status, 200);
    adminCookie = loginRes.cookie || adminCookie;
  });
});

describe('User Management', () => {
  it('should list users (admin)', async () => {
    const res = await request('GET', '/api/users', null, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body));
    assert.ok(res.body.length >= 2);
  });

  it('should reject user list (viewer)', async () => {
    const res = await request('GET', '/api/users', null, viewerCookie);
    assert.strictEqual(res.status, 403);
  });
});

describe('Domains API', () => {
  it('should create a domain (admin)', async () => {
    const res = await request('POST', '/api/domains', {
      domain: 'example.com',
      display_name: 'Example',
    }, adminCookie);
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.domain, 'example.com');
    testDomainId = res.body.id;
  });

  it('should reject domain creation (viewer)', async () => {
    const res = await request('POST', '/api/domains', {
      domain: 'viewer-domain.com',
    }, viewerCookie);
    assert.strictEqual(res.status, 403);
  });

  it('should list domains', async () => {
    const res = await request('GET', '/api/domains', null, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body));
    assert.ok(res.body.length >= 1);
  });

  it('should reject invalid domain format', async () => {
    const res = await request('POST', '/api/domains', {
      domain: 'not-a-domain',
    }, adminCookie);
    assert.strictEqual(res.status, 400);
  });

  it('should reject duplicate domain', async () => {
    const res = await request('POST', '/api/domains', {
      domain: 'example.com',
    }, adminCookie);
    assert.strictEqual(res.status, 409);
  });

  it('should update domain', async () => {
    const res = await request('PUT', `/api/domains/${testDomainId}`, {
      display_name: 'Updated Example',
      scan_interval_minutes: 120,
    }, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.display_name, 'Updated Example');
  });

  it('should get dashboard', async () => {
    const res = await request('GET', '/api/dashboard', null, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.total_domains >= 1);
  });
});

describe('Tags API', () => {
  let tagId;

  it('should create a tag (admin)', async () => {
    const res = await request('POST', '/api/tags', {
      name: 'production',
      color: '#ef4444',
    }, adminCookie);
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.name, 'production');
    tagId = res.body.id;
  });

  it('should list tags', async () => {
    const res = await request('GET', '/api/tags', null, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.length >= 1);
  });

  it('should assign tag to domain', async () => {
    const res = await request('POST', `/api/domains/${testDomainId}/tags/${tagId}`, {}, adminCookie);
    assert.strictEqual(res.status, 200);
  });

  it('should delete tag', async () => {
    const res = await request('DELETE', `/api/tags/${tagId}`, null, adminCookie);
    assert.strictEqual(res.status, 200);
  });
});

describe('API Keys', () => {
  let apiKeyPlaintext;
  let apiKeyId;

  it('should generate an API key', async () => {
    const res = await request('POST', '/api/auth/api-keys', {
      name: 'Test Key',
    }, adminCookie);
    assert.strictEqual(res.status, 201);
    assert.ok(res.body.key);
    assert.ok(res.body.key.startsWith('dnss_'));
    apiKeyPlaintext = res.body.key;
    apiKeyId = res.body.id;
  });

  it('should list API keys', async () => {
    const res = await request('GET', '/api/auth/api-keys', null, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.length >= 1);
    // Should not expose the full key
    assert.ok(!res.body[0].key);
  });

  it('should authenticate with API key', async () => {
    const res = await request('GET', '/api/domains', null, null);
    // Override cookie with Bearer token
    const url = new URL('/api/domains', BASE_URL);
    const opts = {
      method: 'GET',
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      headers: {
        'Authorization': `Bearer ${apiKeyPlaintext}`,
        'Origin': BASE_URL,
      },
    };
    const apiRes = await new Promise((resolve, reject) => {
      const req = http.request(opts, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
      });
      req.on('error', reject);
      req.end();
    });
    assert.strictEqual(apiRes.status, 200);
    assert.ok(Array.isArray(apiRes.body));
  });

  it('should delete API key', async () => {
    const res = await request('DELETE', `/api/auth/api-keys/${apiKeyId}`, null, adminCookie);
    assert.strictEqual(res.status, 200);
  });
});

describe('Audit Log', () => {
  it('should have audit entries', async () => {
    const res = await request('GET', '/api/settings/audit-log?page=1&limit=10', null, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.rows));
    assert.ok(res.body.total >= 0);
  });
});

describe('Cleanup', () => {
  it('should delete test domain', async () => {
    if (testDomainId) {
      const res = await request('DELETE', `/api/domains/${testDomainId}`, null, adminCookie);
      assert.strictEqual(res.status, 200);
    }
  });

  it('should logout', async () => {
    const res = await request('POST', '/api/auth/logout', null, adminCookie);
    assert.strictEqual(res.status, 200);
  });
});
