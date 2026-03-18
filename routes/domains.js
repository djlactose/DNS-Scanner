'use strict';
const router = require('express').Router();
const multer = require('multer');
const { query } = require('../db');
const { requireAuth, requireAdmin, validateId, validateDomain, escapeCsv, escapeHtml, logAudit, getTagFilter } = require('../middleware');
const { SCAN_STATUS, SCAN_TRIGGER } = require('../constants');
const { broadcastSSE } = require('../sse');
const { getSetting } = require('../settings-service');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });

// ─── List domains ───
router.get('/domains', requireAuth, async (req, res) => {
  try {
    const tag = req.query.tag;
    const tagAccess = await getTagFilter(req);
    let sql = `
      SELECT d.*,
        (SELECT COUNT(*) FROM dns_records WHERE domain_id = d.id AND removed_at IS NULL) as record_count,
        (SELECT COUNT(*) FROM dns_records dr
          JOIN health_checks hc ON hc.id = (SELECT id FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1)
          WHERE dr.domain_id = d.id AND dr.removed_at IS NULL AND hc.status = 'dead') as dead_count,
        (SELECT started_at FROM scans WHERE domain_id = d.id ORDER BY started_at DESC LIMIT 1) as last_scan,
        COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'color', t.color))
          FROM tags t JOIN domain_tags dt ON dt.tag_id = t.id WHERE dt.domain_id = d.id), '[]') as tags
      FROM domains d
    `;
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (tag) {
      conditions.push(`d.id IN (SELECT domain_id FROM domain_tags dt JOIN tags t ON t.id = dt.tag_id WHERE t.name = $${paramIndex})`);
      params.push(tag);
      paramIndex++;
    }

    if (tagAccess.clause) {
      conditions.push(tagAccess.clause.replace('$TAG_PARAM', `$${paramIndex}::int[]`));
      params.push(tagAccess.params[0]);
      paramIndex++;
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }

    sql += ' ORDER BY d.domain';
    const result = await query(sql, params);
    res.json(result.rows);
  } catch (err) {
    console.error('[DOMAINS] List error:', err.message);
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
});

// ─── Create domain ───
router.post('/domains', requireAdmin, async (req, res) => {
  try {
    const { domain, display_name, scan_interval_minutes } = req.body;
    if (!validateDomain(domain)) return res.status(400).json({ error: 'Invalid domain format' });
    const maxDomains = parseInt(await getSetting('max_domains'), 10) || 50;
    const countResult = await query('SELECT COUNT(*) as count FROM domains');
    if (parseInt(countResult.rows[0].count) >= maxDomains) return res.status(400).json({ error: `Max ${maxDomains} domains allowed` });
    const interval = Math.max(15, Math.min(10080, parseInt(scan_interval_minutes) || 360));
    const result = await query(
      'INSERT INTO domains (domain, display_name, scan_interval_minutes, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
      [domain.toLowerCase(), display_name || null, interval, req.session.userId]
    );
    logAudit(req, 'domain.create', 'domain', result.rows[0].id);
    console.log(`[DOMAINS] Added: ${domain} by user ${req.session.userId}`);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Domain already exists' });
    res.status(500).json({ error: 'Failed to add domain' });
  }
});

// ─── Update domain ───
router.put('/domains/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const { display_name, scan_interval_minutes, enabled } = req.body;
    const interval = scan_interval_minutes ? Math.max(15, Math.min(10080, parseInt(scan_interval_minutes))) : undefined;
    const result = await query(
      `UPDATE domains SET
        display_name = COALESCE($1, display_name),
        scan_interval_minutes = COALESCE($2, scan_interval_minutes),
        enabled = COALESCE($3, enabled),
        updated_at = NOW()
      WHERE id = $4 RETURNING *`,
      [display_name, interval, enabled, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });
    logAudit(req, 'domain.update', 'domain', req.params.id);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update domain' }); }
});

// ─── Delete domain ───
router.delete('/domains/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const result = await query('DELETE FROM domains WHERE id = $1 RETURNING domain', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });
    logAudit(req, 'domain.delete', 'domain', req.params.id);
    console.log(`[DOMAINS] Deleted: ${result.rows[0].domain} by user ${req.session.userId}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete domain' }); }
});

// ─── Domain tags ───
router.post('/domains/:id/tags/:tagId', requireAdmin, async (req, res) => {
  try {
    const domainId = parseInt(req.params.id, 10);
    const tagId = parseInt(req.params.tagId, 10);
    if (!Number.isInteger(domainId) || domainId < 1 || !Number.isInteger(tagId) || tagId < 1) return res.status(400).json({ error: 'Invalid IDs' });
    await query('INSERT INTO domain_tags (domain_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [domainId, tagId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to add tag' }); }
});

router.delete('/domains/:id/tags/:tagId', requireAdmin, async (req, res) => {
  try {
    const domainId = parseInt(req.params.id, 10);
    const tagId = parseInt(req.params.tagId, 10);
    if (!Number.isInteger(domainId) || domainId < 1 || !Number.isInteger(tagId) || tagId < 1) return res.status(400).json({ error: 'Invalid IDs' });
    await query('DELETE FROM domain_tags WHERE domain_id = $1 AND tag_id = $2', [domainId, tagId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to remove tag' }); }
});

// ─── Bulk import ───
router.post('/domains/import', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'CSV file required' });
    const csv = req.file.buffer.toString('utf8');
    const lines = csv.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('domain,'));
    if (lines.length > 100) return res.status(400).json({ error: 'Max 100 domains per import' });

    const results = { imported: 0, skipped: 0, errors: [] };
    for (const line of lines) {
      const parts = line.split(',').map(p => p.trim());
      const domain = parts[0]?.toLowerCase();
      if (!validateDomain(domain)) { results.errors.push(`Invalid: ${parts[0]}`); results.skipped++; continue; }
      try {
        const interval = Math.max(15, Math.min(10080, parseInt(parts[2]) || 360));
        await query(
          'INSERT INTO domains (domain, display_name, scan_interval_minutes, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (domain) DO NOTHING',
          [domain, parts[1] || null, interval, req.session.userId]
        );
        results.imported++;
        if (parts[3]) {
          const tagNames = parts[3].split(';').map(t => t.trim()).filter(Boolean);
          for (const tagName of tagNames) {
            const tagResult = await query('INSERT INTO tags (name, created_by) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id', [tagName, req.session.userId]);
            const domainResult = await query('SELECT id FROM domains WHERE domain = $1', [domain]);
            if (domainResult.rows.length && tagResult.rows.length) {
              await query('INSERT INTO domain_tags (domain_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [domainResult.rows[0].id, tagResult.rows[0].id]);
            }
          }
        }
      } catch (err) { results.errors.push(`Error: ${domain} - ${err.message}`); results.skipped++; }
    }
    logAudit(req, 'domain.bulk_import', 'domain', null, { imported: results.imported, skipped: results.skipped });
    console.log(`[DOMAINS] Bulk import: ${results.imported} imported, ${results.skipped} skipped`);
    res.json(results);
  } catch (err) { res.status(500).json({ error: 'Import failed' }); }
});

// ─── Bulk scan ───
router.post('/domains/bulk/scan', requireAdmin, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'Array of domain IDs required' });
    const { performScan } = require('../scanner');
    let started = 0;

    for (const id of ids) {
      const domainResult = await query('SELECT * FROM domains WHERE id = $1', [id]);
      if (domainResult.rows.length === 0) continue;
      const running = await query('SELECT id FROM scans WHERE domain_id = $1 AND status = $2', [id, SCAN_STATUS.RUNNING]);
      if (running.rows.length > 0) continue;
      const scanResult = await query(
        'INSERT INTO scans (domain_id, trigger, triggered_by) VALUES ($1, $2, $3) RETURNING id',
        [id, SCAN_TRIGGER.MANUAL, req.session.userId]
      );
      performScan(domainResult.rows[0], scanResult.rows[0].id).catch(err => console.error(`[SCAN] Error scanning domain ${id}:`, err.message));
      started++;
    }

    broadcastSSE({ type: 'scan_all_started', count: started });
    res.json({ started, total: ids.length });
  } catch (err) { res.status(500).json({ error: 'Failed to start bulk scan' }); }
});

// ─── Bulk delete ───
router.post('/domains/bulk/delete', requireAdmin, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'Array of domain IDs required' });
    let deleted = 0;
    for (const id of ids) {
      const result = await query('DELETE FROM domains WHERE id = $1 RETURNING domain', [id]);
      if (result.rows.length > 0) deleted++;
    }
    logAudit(req, 'domain.bulk_delete', 'domain', null, { count: deleted });
    res.json({ deleted, total: ids.length });
  } catch (err) { res.status(500).json({ error: 'Failed to bulk delete' }); }
});

// ─── Bulk tag ───
router.post('/domains/bulk/tag', requireAdmin, async (req, res) => {
  try {
    const { ids, tagId } = req.body;
    if (!Array.isArray(ids) || ids.length === 0 || !tagId) return res.status(400).json({ error: 'Array of domain IDs and tagId required' });
    let tagged = 0;
    for (const id of ids) {
      await query('INSERT INTO domain_tags (domain_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [id, tagId]);
      tagged++;
    }
    res.json({ tagged, total: ids.length });
  } catch (err) { res.status(500).json({ error: 'Failed to bulk tag' }); }
});

// ─── Manual scan ───
router.post('/domains/:id/scan', requireAuth, validateId, async (req, res) => {
  try {
    const domainResult = await query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domainResult.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });
    const running = await query('SELECT id FROM scans WHERE domain_id = $1 AND status = $2', [req.params.id, SCAN_STATUS.RUNNING]);
    if (running.rows.length > 0) return res.status(409).json({ error: 'Scan already running' });
    const scanResult = await query(
      'INSERT INTO scans (domain_id, trigger, triggered_by) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, SCAN_TRIGGER.MANUAL, req.session.userId]
    );
    console.log(`[SCAN] Manual scan started for ${domainResult.rows[0].domain} by user ${req.session.userId}`);
    const { performScan } = require('../scanner');
    performScan(domainResult.rows[0], scanResult.rows[0].id).catch(err => {
      console.error(`[SCAN] Error:`, err.message);
    });
    broadcastSSE({ type: 'scan_started', domainId: req.params.id, scanId: scanResult.rows[0].id });
    res.json(scanResult.rows[0]);
  } catch (err) {
    console.error('[SCAN] Error:', err.message);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

// ─── Scan all ───
router.post('/scan-all', requireAuth, async (req, res) => {
  try {
    const domains = await query('SELECT * FROM domains WHERE enabled = TRUE');
    const { performScan } = require('../scanner');
    let started = 0;
    const pending = [];
    for (const domain of domains.rows) {
      const running = await query('SELECT id FROM scans WHERE domain_id = $1 AND status = $2', [domain.id, SCAN_STATUS.RUNNING]);
      if (running.rows.length > 0) continue;
      const scanResult = await query(
        'INSERT INTO scans (domain_id, trigger, triggered_by) VALUES ($1, $2, $3) RETURNING id',
        [domain.id, SCAN_TRIGGER.MANUAL, req.session.userId]
      );
      const p = performScan(domain, scanResult.rows[0].id).catch(err => console.error(`[SCAN] Error scanning ${domain.domain}:`, err.message));
      pending.push(p);
      started++;
      if (pending.length >= 5) {
        await Promise.race(pending);
        for (let i = pending.length - 1; i >= 0; i--) {
          const settled = await Promise.race([pending[i].then(() => true, () => true), Promise.resolve(false)]);
          if (settled) pending.splice(i, 1);
        }
      }
    }
    broadcastSSE({ type: 'scan_all_started', count: started });
    res.json({ started, total: domains.rows.length });
  } catch (err) { res.status(500).json({ error: 'Failed to start scans' }); }
});

// ─── Scan history ───
router.get('/domains/:id/scans', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM scans WHERE domain_id = $1 ORDER BY started_at DESC LIMIT 50', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch scans' }); }
});

// ─── Scan detail ───
router.get('/scans/:id', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM scans WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Scan not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch scan' }); }
});

// ─── Records with health ───
router.get('/domains/:id/records', requireAuth, validateId, async (req, res) => {
  try {
    const status = req.query.status;
    let sql = `
      SELECT dr.*,
        (SELECT row_to_json(hc) FROM (
          SELECT status, status_code, response_ms, error_message, check_method, ports_open, ssl_valid, ssl_expires_at, ssl_error, propagation_results, checked_at
          FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1
        ) hc) as latest_health,
        (SELECT COUNT(*) FROM health_checks WHERE record_id = dr.id AND status = 'dead') as consecutive_failures
      FROM dns_records dr
      WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
    `;
    const params = [req.params.id];

    if (status === 'dead') {
      sql += ` AND dr.id IN (SELECT record_id FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) AND (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) = 'dead'`;
    } else if (status === 'alive') {
      sql += ` AND (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) = 'alive'`;
    } else if (status === 'new') {
      sql += ` AND dr.first_seen > NOW() - INTERVAL '24 hours'`;
    } else if (status === 'changed') {
      sql += ` AND dr.id IN (SELECT record_id FROM dns_changes WHERE domain_id = $1 AND changed_at > NOW() - INTERVAL '24 hours')`;
    }

    sql += ' ORDER BY dr.record_type, dr.name';
    const result = await query(sql, params);
    res.json(result.rows);
  } catch (err) {
    console.error('[RECORDS] Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch records' });
  }
});

// ─── Health check history ───
router.get('/records/:id/history', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM health_checks WHERE record_id = $1 ORDER BY checked_at DESC LIMIT 100', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch history' }); }
});

// ─── Record changes ───
router.get('/records/:id/changes', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM dns_changes WHERE record_id = $1 ORDER BY changed_at DESC LIMIT 50', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch changes' }); }
});

// ─── Domain changes ───
router.get('/domains/:id/changes', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT * FROM dns_changes WHERE domain_id = $1 ORDER BY changed_at DESC LIMIT 100', [req.params.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch changes' }); }
});

// ─── Dismiss dead record ───
router.put('/records/:id/dismiss', requireAuth, validateId, async (req, res) => {
  try {
    await query('UPDATE dns_records SET dismissed = $1, dismissed_by = $2 WHERE id = $3', [req.body.dismissed !== false, req.session.userId, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to dismiss record' }); }
});

// ─── Port rescan ───
router.post('/records/:id/port-scan', requireAuth, validateId, async (req, res) => {
  try {
    const { portScanRecord } = require('../scanner');
    const result = await portScanRecord(parseInt(req.params.id));
    res.json(result);
  } catch (err) {
    console.error('[PORT-SCAN] Error:', err.message);
    res.status(500).json({ error: 'Port scan failed' });
  }
});

// ─── CSV export ───
router.get('/domains/:id/export/csv', requireAuth, validateId, async (req, res) => {
  try {
    const domain = await query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domain.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });

    const records = await query(`
      SELECT dr.record_type, dr.name, dr.value, dr.priority, dr.ttl, dr.first_seen, dr.last_seen,
        (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as health_status,
        (SELECT response_ms FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as response_ms
      FROM dns_records dr WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
      ORDER BY dr.record_type, dr.name
    `, [req.params.id]);

    let csv = 'Type,Name,Value,Priority,TTL,Status,Response(ms),First Seen,Last Seen\n';
    for (const r of records.rows) {
      csv += `${r.record_type},${r.name},"${escapeCsv(r.value)}",${r.priority || ''},${r.ttl || ''},${r.health_status || 'unknown'},${r.response_ms || ''},${r.first_seen},${r.last_seen}\n`;
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${domain.rows[0].domain}-records.csv"`);
    res.send(csv);
  } catch (err) { res.status(500).json({ error: 'Export failed' }); }
});

// ─── HTML report ───
router.get('/domains/:id/export/report', requireAuth, validateId, async (req, res) => {
  try {
    const domain = await query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domain.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });

    const records = await query(`
      SELECT dr.*,
        (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as health_status,
        (SELECT response_ms FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as response_ms,
        (SELECT ssl_valid FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as ssl_valid,
        (SELECT ssl_expires_at FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) as ssl_expires_at
      FROM dns_records dr WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
      ORDER BY dr.record_type, dr.name
    `, [req.params.id]);

    const d = domain.rows[0];
    const alive = records.rows.filter(r => r.health_status === 'alive').length;
    const dead = records.rows.filter(r => r.health_status === 'dead').length;

    let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>DNS Report: ${escapeHtml(d.domain)}</title>
    <style>
      body{font-family:-apple-system,sans-serif;max-width:900px;margin:0 auto;padding:20px;color:#333}
      h1{border-bottom:2px solid #333;padding-bottom:10px}
      .summary{display:flex;gap:20px;margin:20px 0}
      .stat{padding:15px;border-radius:8px;text-align:center;min-width:100px}
      .stat-alive{background:#dcfce7;color:#166534} .stat-dead{background:#fef2f2;color:#991b1b}
      .stat h2{margin:0;font-size:28px} .stat p{margin:5px 0 0}
      table{width:100%;border-collapse:collapse;margin:20px 0}
      th,td{border:1px solid #ddd;padding:8px 12px;text-align:left}
      th{background:#f9fafb;font-weight:600}
      .status-alive{color:#16a34a;font-weight:600} .status-dead{color:#dc2626;font-weight:600}
      .status-skipped{color:#9ca3af} .status-takeover_risk{color:#7c3aed;font-weight:600}
      @media print{body{padding:0} .no-print{display:none}}
    </style></head><body>
    <h1>DNS Report: ${escapeHtml(d.display_name || d.domain)}</h1>
    <p>Generated: ${new Date().toISOString()}</p>
    <div class="summary">
      <div class="stat stat-alive"><h2>${alive}</h2><p>Alive</p></div>
      <div class="stat stat-dead"><h2>${dead}</h2><p>Dead</p></div>
      <div class="stat"><h2>${records.rows.length}</h2><p>Total</p></div>
    </div>
    <table><thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Status</th><th>Response</th><th>SSL</th></tr></thead><tbody>`;

    for (const r of records.rows) {
      const statusClass = `status-${r.health_status || 'unknown'}`;
      html += `<tr><td>${escapeHtml(r.record_type)}</td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.value)}</td>
        <td class="${statusClass}">${(r.health_status || 'unknown').toUpperCase()}</td>
        <td>${r.response_ms ? r.response_ms + 'ms' : '-'}</td>
        <td>${r.ssl_valid === true ? 'Valid' : r.ssl_valid === false ? 'Invalid' : '-'}</td></tr>`;
    }

    html += `</tbody></table>
    <button class="no-print" onclick="window.print()" style="padding:10px 20px;background:#3b82f6;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:16px">Print / Save PDF</button>
    </body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) { res.status(500).json({ error: 'Report generation failed' }); }
});

// ─── Propagation ───
router.get('/domains/:id/propagation', requireAuth, validateId, async (req, res) => {
  try {
    const records = await query(`
      SELECT dr.id, dr.record_type, dr.name, dr.value, hc.propagation_results
      FROM dns_records dr
      LEFT JOIN LATERAL (SELECT propagation_results FROM health_checks WHERE record_id = dr.id AND propagation_results IS NOT NULL ORDER BY checked_at DESC LIMIT 1) hc ON TRUE
      WHERE dr.domain_id = $1 AND dr.removed_at IS NULL
      ORDER BY dr.record_type, dr.name
    `, [req.params.id]);
    res.json(records.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch propagation data' }); }
});

// ─── WHOIS ───
router.get('/domains/:id/whois', requireAuth, validateId, async (req, res) => {
  try {
    const result = await query('SELECT dw.*, d.domain FROM domain_whois dw JOIN domains d ON d.id = dw.domain_id WHERE dw.domain_id = $1', [req.params.id]);
    res.json(result.rows[0] || null);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch whois data' }); }
});

module.exports = router;
