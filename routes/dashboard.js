'use strict';
const router = require('express').Router();
const { query } = require('../db');
const { requireAuth, getTagFilter } = require('../middleware');

// ─── Dashboard ───
router.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const tag = req.query.tag;
    const tagAccess = await getTagFilter(req);
    let domainFilter = '';
    const params = [];
    let idx = 1;

    if (tag) {
      domainFilter += ` AND d.id IN (SELECT domain_id FROM domain_tags dt JOIN tags t ON t.id = dt.tag_id WHERE t.name = $${idx})`;
      params.push(tag);
      idx++;
    }

    if (tagAccess.clause) {
      domainFilter += ` AND ${tagAccess.clause.replace('$TAG_PARAM', `$${idx}::int[]`)}`;
      params.push(tagAccess.params[0]);
      idx++;
    }

    const stats = await query(`
      SELECT
        (SELECT COUNT(*) FROM domains d WHERE enabled = TRUE ${domainFilter}) as total_domains,
        (SELECT COUNT(*) FROM dns_records dr JOIN domains d ON d.id = dr.domain_id WHERE dr.removed_at IS NULL ${domainFilter}) as total_records
    `, params);

    const deadRecords = await query(`
      SELECT dr.*, d.domain, d.display_name,
        hc.status, hc.checked_at, hc.error_message, hc.ports_open
      FROM dns_records dr
      JOIN domains d ON d.id = dr.domain_id
      JOIN LATERAL (
        SELECT * FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1
      ) hc ON TRUE
      WHERE dr.removed_at IS NULL AND dr.dismissed = FALSE
        AND hc.status IN ('dead', 'takeover_risk')
        ${domainFilter}
      ORDER BY hc.status = 'takeover_risk' DESC, hc.checked_at DESC
      LIMIT 50
    `, params);

    const recentChanges = await query(`
      SELECT dc.*, d.domain FROM dns_changes dc
      JOIN domains d ON d.id = dc.domain_id
      WHERE 1=1 ${domainFilter}
      ORDER BY dc.changed_at DESC LIMIT 20
    `, params);

    const aliveCount = await query(`
      SELECT COUNT(DISTINCT dr.id) as count
      FROM dns_records dr
      JOIN domains d ON d.id = dr.domain_id
      JOIN LATERAL (SELECT status FROM health_checks WHERE record_id = dr.id ORDER BY checked_at DESC LIMIT 1) hc ON TRUE
      WHERE dr.removed_at IS NULL AND hc.status = 'alive' ${domainFilter}
    `, params);

    res.json({
      total_domains: parseInt(stats.rows[0].total_domains),
      total_records: parseInt(stats.rows[0].total_records),
      alive_records: parseInt(aliveCount.rows[0].count),
      dead_records: deadRecords.rows,
      recent_changes: recentChanges.rows,
    });
  } catch (err) {
    console.error('[DASHBOARD] Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch dashboard' });
  }
});

module.exports = router;
