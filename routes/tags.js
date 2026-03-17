'use strict';
const router = require('express').Router();
const { query } = require('../db');
const { requireAuth, requireAdmin, validateId, logAudit } = require('../middleware');

// ─── List tags ───
router.get('/', requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM tags ORDER BY name');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch tags' }); }
});

// ─── Create tag ───
router.post('/', requireAdmin, async (req, res) => {
  try {
    const { name, color } = req.body;
    if (!name || name.length > 50) return res.status(400).json({ error: 'Tag name required (max 50 chars)' });
    const result = await query('INSERT INTO tags (name, color, created_by) VALUES ($1, $2, $3) RETURNING *', [name, color || '#3b82f6', req.session.userId]);
    logAudit(req, 'tag.create', 'tag', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Tag name already exists' });
    res.status(500).json({ error: 'Failed to create tag' });
  }
});

// ─── Update tag ───
router.put('/:id', requireAdmin, validateId, async (req, res) => {
  try {
    const { name, color } = req.body;
    const result = await query('UPDATE tags SET name = COALESCE($1, name), color = COALESCE($2, color) WHERE id = $3 RETURNING *', [name, color, req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tag not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update tag' }); }
});

// ─── Delete tag ───
router.delete('/:id', requireAdmin, validateId, async (req, res) => {
  try {
    await query('DELETE FROM tags WHERE id = $1', [req.params.id]);
    logAudit(req, 'tag.delete', 'tag', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete tag' }); }
});

module.exports = router;
