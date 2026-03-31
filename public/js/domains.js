Object.assign(App, {
  _domains: null,
  _currentDomain: null,
  _currentRecords: null,
  _currentFilter: 'all',
  _sortField: 'record_type',
  _sortDir: 1,

  // ─── Domain List ───
  async renderDomains() {
    const isAdmin = this.user?.role === 'admin';
    this.selectedDomains.clear();
    this.renderLayout(`
      <div class="page-header"><h2>Domains</h2>
        <div style="display:flex;gap:8px">
          ${isAdmin ? '<button class="btn-primary" onclick="App.showAddDomain()">+ Add Domain</button>' : ''}
          <button class="btn-secondary" onclick="App.scanAll()">Scan All Now</button>
        </div>
      </div>
      <div class="search-bar">
        <input id="domain-search" placeholder="Search domains..." oninput="App.filterDomains()">
        <select id="domain-filter" onchange="App.filterDomains()">
          <option value="all">All</option><option value="dead">Has Dead Records</option><option value="healthy">Healthy</option><option value="disabled">Disabled</option>
        </select>
        <select id="domain-tag-filter" onchange="App.filterDomains()">
          <option value="">All Tags</option>
        </select>
        ${isAdmin ? '<button class="btn-secondary" onclick="App.showImport()">Import CSV</button>' : ''}
        ${isAdmin ? `<label style="display:flex;align-items:center;gap:4px;font-size:13px;cursor:pointer"><input type="checkbox" id="select-all-toggle" onclick="App.toggleSelectAll()"> Select All</label>` : ''}
      </div>
      <div id="domain-list"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div>
      ${isAdmin ? `<div id="bulk-bar" class="bulk-bar" style="display:none">
        <span id="bulk-count">0 selected</span>
        <button class="btn-secondary btn-sm" onclick="App.bulkScan()">Scan Selected</button>
        <button class="btn-danger btn-sm" onclick="App.bulkDelete()">Delete Selected</button>
        <button class="btn-secondary btn-sm" onclick="App.bulkTag()">Tag Selected</button>
      </div>` : ''}
    `);
    try {
      this._domains = await this.api('/domains');
      // Populate tag filter
      this.populateTagFilter();
      this.filterDomains();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  populateTagFilter() {
    const select = document.getElementById('domain-tag-filter');
    if (!select || !this._domains) return;
    const tagSet = new Map();
    for (const d of this._domains) {
      const tags = (typeof d.tags === 'string' ? JSON.parse(d.tags) : d.tags) || [];
      for (const t of tags) {
        if (t && t.name) tagSet.set(t.name, t);
      }
    }
    for (const [name] of tagSet) {
      const opt = document.createElement('option');
      opt.value = name;
      opt.textContent = name;
      select.appendChild(opt);
    }
  },

  filterDomains() {
    const search = (document.getElementById('domain-search')?.value || '').toLowerCase();
    const filter = document.getElementById('domain-filter')?.value || 'all';
    const tagFilter = document.getElementById('domain-tag-filter')?.value || '';
    const el = document.getElementById('domain-list');
    if (!el || !this._domains) return;

    let filtered = this._domains;
    if (search) filtered = filtered.filter(d => d.domain.includes(search) || (d.display_name || '').toLowerCase().includes(search));
    if (filter === 'dead') filtered = filtered.filter(d => parseInt(d.dead_count) > 0);
    else if (filter === 'healthy') filtered = filtered.filter(d => parseInt(d.dead_count) === 0 && d.enabled);
    else if (filter === 'disabled') filtered = filtered.filter(d => !d.enabled);

    if (tagFilter) {
      filtered = filtered.filter(d => {
        const tags = (typeof d.tags === 'string' ? JSON.parse(d.tags) : d.tags) || [];
        return tags.some(t => t && t.name === tagFilter);
      });
    }

    if (filtered.length === 0) {
      el.innerHTML = '<div class="empty-state"><div class="empty-icon">&#127760;</div><p>No domains found</p>' +
        (this.user?.role === 'admin' ? '<button class="btn-primary" onclick="App.showAddDomain()">Add your first domain</button>' : '') + '</div>';
      return;
    }

    // Sort: dead first
    filtered.sort((a, b) => parseInt(b.dead_count || 0) - parseInt(a.dead_count || 0));

    const isAdmin = this.user?.role === 'admin';
    el.innerHTML = filtered.map(d => {
      const deadCount = parseInt(d.dead_count || 0);
      const dotClass = this.scanningDomains.has(d.id) ? 'scanning' : deadCount > 0 ? 'dead' : 'alive';
      const tags = (typeof d.tags === 'string' ? JSON.parse(d.tags) : d.tags) || [];
      const tagHtml = tags.filter(t => t && t.name).map(t => `<span class="tag" style="background:${this.esc(t.color)}">${this.esc(t.name)}</span>`).join('');
      return `<div class="domain-card card" data-id="${d.id}" onclick="App.navigate('domains/${d.id}')">
        ${isAdmin ? `<input type="checkbox" class="domain-check" data-id="${d.id}" onclick="event.stopPropagation(); App.updateBulkBar()" ${this.selectedDomains.has(d.id) ? 'checked' : ''}>` : ''}
        <div class="domain-dot ${dotClass}"></div>
        <div class="domain-info">
          <div class="domain-name">${this.esc(d.display_name || d.domain)} ${tagHtml}</div>
          <div class="domain-meta">${this.esc(d.domain)} &middot; ${d.record_count || 0} records &middot; ${deadCount > 0 ? `<span style="color:var(--status-dead)">${deadCount} dead</span>` : '0 dead'} &middot; Last scan: ${this.timeAgo(d.last_scan)}</div>
        </div>
        <div class="domain-actions" onclick="event.stopPropagation()">
          <button class="btn-sm btn-secondary" onclick="App.scanDomain(${d.id})" ${this.scanningDomains.has(d.id) ? 'disabled' : ''}>${this.scanningDomains.has(d.id) ? 'Scanning...' : 'Scan Now'}</button>
          ${isAdmin ? `<button class="btn-sm btn-icon" onclick="App.showEditDomain(${d.id})">&#9998;</button><button class="btn-sm btn-icon" onclick="App.deleteDomain(${d.id}, '${this.esc(d.domain)}')" style="color:var(--danger)">&#10005;</button>` : ''}
        </div>
        ${this.scanningDomains.has(d.id) ? `<div class="scan-progress" data-domain-id="${d.id}"><div class="progress-track"><div class="progress-fill" style="width:0%"></div></div><div class="progress-label">Starting scan...</div></div>` : ''}
      </div>`;
    }).join('');
  },

  // ─── Bulk Actions ───
  updateBulkBar() {
    this.selectedDomains.clear();
    document.querySelectorAll('.domain-check:checked').forEach(cb => {
      this.selectedDomains.add(parseInt(cb.dataset.id));
    });
    const bar = document.getElementById('bulk-bar');
    const count = document.getElementById('bulk-count');
    if (bar) {
      bar.style.display = this.selectedDomains.size > 0 ? 'flex' : 'none';
    }
    if (count) {
      count.textContent = `${this.selectedDomains.size} selected`;
    }
  },

  toggleSelectAll() {
    const toggle = document.getElementById('select-all-toggle');
    const checked = toggle?.checked || false;
    document.querySelectorAll('.domain-check').forEach(cb => {
      cb.checked = checked;
    });
    this.updateBulkBar();
  },

  async bulkScan() {
    if (this.selectedDomains.size === 0) return;
    try {
      const result = await this.api('/domains/bulk/scan', { method: 'POST', body: { ids: [...this.selectedDomains] } });
      this.toast(`Started scanning ${result.started || this.selectedDomains.size} domain(s)`, 'info');
      for (const id of this.selectedDomains) this.scanningDomains.add(id);
      this.selectedDomains.clear();
      this.filterDomains();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async bulkDelete() {
    if (this.selectedDomains.size === 0) return;
    if (!confirm(`Delete ${this.selectedDomains.size} domain(s) and all their scan history?`)) return;
    try {
      await this.api('/domains/bulk/delete', { method: 'POST', body: { ids: [...this.selectedDomains] } });
      this.toast(`Deleted ${this.selectedDomains.size} domain(s)`, 'success');
      this.selectedDomains.clear();
      this.renderDomains();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async bulkTag() {
    if (this.selectedDomains.size === 0) return;
    try {
      const tags = await this.api('/tags');
      if (tags.length === 0) { this.toast('No tags available. Create tags in Settings first.', 'warning'); return; }
      this.showModal('Tag Selected Domains', `
        <div class="form-group"><label>Tag</label>
          <select id="modal-bulk-tag">
            ${tags.map(t => `<option value="${t.id}">${this.esc(t.name)}</option>`).join('')}
          </select>
        </div>
        <div class="form-group"><label>Action</label>
          <select id="modal-bulk-tag-action">
            <option value="add">Add tag</option>
            <option value="remove">Remove tag</option>
          </select>
        </div>
      `, async () => {
        const tagId = parseInt(document.getElementById('modal-bulk-tag').value);
        const action = document.getElementById('modal-bulk-tag-action').value;
        await this.api('/domains/bulk/tag', { method: 'POST', body: { ids: [...this.selectedDomains], tagId, action } });
        this.toast('Tags updated', 'success');
        this.selectedDomains.clear();
        this.renderDomains();
      });
    } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── Domain Actions ───
  async scanDomain(id) {
    try {
      this.scanningDomains.add(id);
      if (this._domains) this.filterDomains();
      await this.api(`/domains/${id}/scan`, { method: 'POST' });
      this.toast('Scan started', 'info');
    } catch (e) {
      this.scanningDomains.delete(id);
      if (this._domains) this.filterDomains();
      this.toast(e.message, 'error');
    }
  },

  showAddDomain() {
    this.showModal('Add Domain', `
      <div class="form-group"><label>Domain</label><input id="modal-domain" placeholder="example.com"></div>
      <div class="form-group"><label>Display Name (optional)</label><input id="modal-display" placeholder="My Website"></div>
      <div class="form-group"><label>Scan Interval</label>
        <select id="modal-interval"><option value="60">1 hour</option><option value="180">3 hours</option><option value="360" selected>6 hours</option><option value="720">12 hours</option><option value="1440">24 hours</option></select>
      </div>
    `, async () => {
      await this.api('/domains', { method: 'POST', body: {
        domain: document.getElementById('modal-domain').value,
        display_name: document.getElementById('modal-display').value || undefined,
        scan_interval_minutes: parseInt(document.getElementById('modal-interval').value),
      }});
      this.toast('Domain added', 'success');
      this.renderDomains();
    });
  },

  async showEditDomain(id) {
    const domain = this._domains?.find(d => d.id === id);
    if (!domain) return;
    this.showModal('Edit Domain', `
      <div class="form-group"><label>Display Name</label><input id="modal-display" value="${this.esc(domain.display_name || '')}"></div>
      <div class="form-group"><label>Scan Interval</label>
        <select id="modal-interval">
          ${[60, 180, 360, 720, 1440].map(v => `<option value="${v}" ${domain.scan_interval_minutes === v ? 'selected' : ''}>${v < 60 ? v + ' min' : v / 60 + ' hours'}</option>`).join('')}
        </select>
      </div>
      <div class="form-group"><label class="toggle"><input type="checkbox" id="modal-enabled" ${domain.enabled ? 'checked' : ''}><div class="toggle-track"></div>Enabled</label></div>
    `, async () => {
      await this.api(`/domains/${id}`, { method: 'PUT', body: {
        display_name: document.getElementById('modal-display').value || null,
        scan_interval_minutes: parseInt(document.getElementById('modal-interval').value),
        enabled: document.getElementById('modal-enabled').checked,
      }});
      this.toast('Domain updated', 'success');
      this.renderDomains();
    });
  },

  async deleteDomain(id, name) {
    if (!confirm(`Delete ${name} and all scan history?`)) return;
    try {
      await this.api(`/domains/${id}`, { method: 'DELETE' });
      this.toast('Domain deleted', 'success');
      this.renderDomains();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  showImport() {
    this.showModal('Import Domains from CSV', `
      <p style="margin-bottom:12px;font-size:13px;color:var(--text-secondary)">CSV format: domain, display_name, scan_interval, tags (semicolon separated)</p>
      <div class="drop-zone" id="drop-zone" onclick="document.getElementById('csv-file').click()">
        <p>Click or drag a CSV file here</p>
        <input type="file" id="csv-file" accept=".csv" style="display:none" onchange="App.handleCSV(this)">
      </div>
      <div id="import-preview" style="margin-top:12px"></div>
    `, async () => {
      const file = document.getElementById('csv-file').files[0];
      if (!file) throw new Error('Select a CSV file');
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/api/domains/import', { method: 'POST', body: formData });
      if (!res.ok) throw new Error((await res.json()).error);
      const result = await res.json();
      this.toast(`Imported ${result.imported}, skipped ${result.skipped}`, 'success');
      this.renderDomains();
    }, 'Import');

    const dz = document.getElementById('drop-zone');
    if (dz) {
      dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('dragover'); });
      dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
      dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('dragover'); const f = e.dataTransfer.files[0]; if (f) { document.getElementById('csv-file').files = e.dataTransfer.files; App.handleCSV(document.getElementById('csv-file')); } });
    }
  },

  handleCSV(input) {
    const file = input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const lines = e.target.result.split('\n').filter(l => l.trim());
      const preview = document.getElementById('import-preview');
      if (preview) preview.innerHTML = `<div style="font-size:13px;color:var(--text-secondary)">${lines.length} line(s) found</div>`;
    };
    reader.readAsText(file);
  },

  // ─── Domain Detail ───
  async renderDomainDetail(id) {
    this.renderLayout(`
      <div id="domain-detail"><div class="skeleton skeleton-card"></div></div>
    `, `<a href="#domains">Domains</a> &rsaquo; Loading...`);

    try {
      const [domain] = await Promise.all([this.api(`/domains`).then(ds => ds.find(d => d.id === parseInt(id)))]);
      if (!domain) { this.toast('Domain not found', 'error'); return this.navigate('domains'); }

      const [records, scans, whois] = await Promise.all([
        this.api(`/domains/${id}/records`),
        this.api(`/domains/${id}/scans`),
        this.api(`/domains/${id}/whois`).catch(() => null),
      ]);

      this._currentDomain = domain;
      this._currentRecords = records;
      this._currentFilter = 'all';

      const el = document.getElementById('domain-detail');
      if (!el) return;

      // Update breadcrumbs
      const bc = document.querySelector('.breadcrumbs');
      if (bc) bc.innerHTML = `<a href="#domains">Domains</a> &rsaquo; ${this.esc(domain.display_name || domain.domain)}`;

      const aliveCount = records.filter(r => r.latest_health?.status === 'alive').length;
      const deadCount = records.filter(r => r.latest_health?.status === 'dead' || r.latest_health?.status === 'takeover_risk').length;
      const newCount = records.filter(r => new Date(r.first_seen) > new Date(Date.now() - 86400000)).length;

      let html = `
        <div class="page-header">
          <div>
            <h2>${this.esc(domain.display_name || domain.domain)}</h2>
            <div style="font-size:13px;color:var(--text-secondary);margin-top:4px">Last scan: ${this.timeAgo(domain.last_scan)} &middot; ${records.length} records found
              ${whois?.expiry_date ? ` &middot; Expires: <span style="color:${new Date(whois.expiry_date) < new Date(Date.now() + 30 * 86400000) ? 'var(--status-dead)' : 'var(--text-secondary)'}">${new Date(whois.expiry_date).toLocaleDateString()}</span>` : ''}</div>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn-primary" onclick="App.scanDomain(${id})" ${this.scanningDomains.has(parseInt(id)) ? 'disabled' : ''}>${this.scanningDomains.has(parseInt(id)) ? 'Scanning...' : 'Scan Now'}</button>
            <button class="btn-secondary" onclick="window.open('/api/domains/${id}/export/csv')">Export CSV</button>
            <button class="btn-secondary" onclick="window.open('/api/domains/${id}/export/report')">Report</button>
          </div>
        </div>
        ${this.scanningDomains.has(parseInt(id)) ? `<div class="scan-progress" data-domain-id="${id}"><div class="progress-track"><div class="progress-fill" style="width:0%"></div></div><div class="progress-label">Starting scan...</div></div>` : ''}
        <div class="filter-pills">
          <span class="pill active" data-filter="all" onclick="App.filterRecords('all', this)">All (${records.length})</span>
          <span class="pill" data-filter="alive" onclick="App.filterRecords('alive', this)">Alive (${aliveCount})</span>
          <span class="pill" data-filter="dead" onclick="App.filterRecords('dead', this)">Dead (${deadCount})</span>
          <span class="pill" data-filter="new" onclick="App.filterRecords('new', this)">New (${newCount})</span>
        </div>
        <div class="card" style="overflow-x:auto">
          <table class="records-table">
            <thead><tr><th onclick="App.sortRecords('record_type')">Type</th><th onclick="App.sortRecords('name')">Name</th><th>Value</th><th onclick="App.sortRecords('status')">Status</th><th>Response</th></tr></thead>
            <tbody id="records-tbody"></tbody>
          </table>
        </div>
      `;

      // Scan history
      if (scans.length > 0) {
        html += `<div class="section-header">Scan History</div><div class="scan-list">`;
        for (const s of scans.slice(0, 15)) {
          html += `<div class="scan-item">
            <span class="scan-time">${this.formatDate(s.started_at)}</span>
            <span class="scan-stats">
              <span>${s.records_found} found</span>
              <span style="color:var(--status-alive)">${s.records_alive} alive</span>
              <span style="color:var(--status-dead)">${s.records_dead} dead</span>
              <span class="status-badge ${s.status}">${s.status}</span>
            </span>
          </div>`;
        }
        html += `</div>`;
      }

      // Trend chart
      html += `<div class="section-header">Health Trend</div><div class="chart-container"><canvas id="trend-chart"></canvas></div>`;

      el.innerHTML = html;
      this.renderRecordsTable();
      this.renderTrendChart(scans);
    } catch (e) { this.toast(e.message, 'error'); }
  },

  filterRecords(filter, el) {
    this._currentFilter = filter;
    document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
    if (el) el.classList.add('active');
    this.renderRecordsTable();
  },

  sortRecords(field) {
    if (this._sortField === field) this._sortDir *= -1;
    else { this._sortField = field; this._sortDir = 1; }
    this.renderRecordsTable();
  },

  renderRecordsTable() {
    const tbody = document.getElementById('records-tbody');
    if (!tbody || !this._currentRecords) return;

    let records = [...this._currentRecords];
    const filter = this._currentFilter;

    if (filter === 'alive') records = records.filter(r => r.latest_health?.status === 'alive');
    else if (filter === 'dead') records = records.filter(r => r.latest_health?.status === 'dead' || r.latest_health?.status === 'takeover_risk');
    else if (filter === 'new') records = records.filter(r => new Date(r.first_seen) > new Date(Date.now() - 86400000));

    const sf = this._sortField;
    records.sort((a, b) => {
      let av = sf === 'status' ? (a.latest_health?.status || '') : (a[sf] || '');
      let bv = sf === 'status' ? (b.latest_health?.status || '') : (b[sf] || '');
      return String(av).localeCompare(String(bv)) * this._sortDir;
    });

    tbody.innerHTML = records.map(r => {
      const h = r.latest_health || {};
      const status = h.status || 'unknown';
      const isNew = new Date(r.first_seen) > new Date(Date.now() - 86400000);
      const rowClass = status === 'dead' ? 'dead-row' : status === 'takeover_risk' ? 'takeover-row' : isNew ? 'new-row' : '';
      const portsOpen = h.ports_open || [];
      const portsStr = portsOpen.length > 0 ? `Ports: ${portsOpen.join(', ')}` : '';
      const sslStr = h.ssl_valid === true ? `SSL: Valid` : h.ssl_valid === false ? `SSL: Invalid` : '';

      return `<tr class="${rowClass}" onclick="App.showRecordDetail(${r.id})">
        <td><strong>${this.esc(r.record_type)}</strong></td>
        <td>${this.esc(r.name)}${r.priority ? ` (pri: ${r.priority})` : ''}</td>
        <td><div class="value-text">${this.esc(r.value)}</div>
          ${portsStr ? `<div style="font-size:12px;color:var(--text-muted);margin-top:2px">${portsStr}</div>` : ''}
          ${sslStr ? `<div style="font-size:12px;color:var(--text-muted)">${sslStr}${h.ssl_expires_at ? ` (exp ${new Date(h.ssl_expires_at).toLocaleDateString()})` : ''}</div>` : ''}
        </td>
        <td><span class="status-badge ${status}">${isNew && status !== 'dead' ? 'NEW' : status.replace('_', ' ')}</span></td>
        <td>${h.response_ms ? `<span class="response-time">${h.response_ms}ms</span>` : '-'}</td>
      </tr>`;
    }).join('');
  },

  renderTrendChart(scans) {
    const canvas = document.getElementById('trend-chart');
    if (!canvas || scans.length < 2) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const w = rect.width, h = rect.height;
    const padding = { top: 20, right: 20, bottom: 30, left: 40 };

    const data = scans.slice(0, 30).reverse();
    const maxVal = Math.max(...data.map(s => s.records_found || 1));

    ctx.clearRect(0, 0, w, h);

    const plotW = w - padding.left - padding.right;
    const plotH = h - padding.top - padding.bottom;
    const xStep = plotW / Math.max(data.length - 1, 1);

    // Grid
    ctx.strokeStyle = '#e2e8f030';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padding.top + (plotH * i / 4);
      ctx.beginPath(); ctx.moveTo(padding.left, y); ctx.lineTo(w - padding.right, y); ctx.stroke();
    }

    // Alive line
    ctx.strokeStyle = '#22c55e';
    ctx.lineWidth = 2;
    ctx.beginPath();
    data.forEach((s, i) => {
      const x = padding.left + i * xStep;
      const y = padding.top + plotH - (s.records_alive / maxVal) * plotH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Dead line
    ctx.strokeStyle = '#ef4444';
    ctx.beginPath();
    data.forEach((s, i) => {
      const x = padding.left + i * xStep;
      const y = padding.top + plotH - (s.records_dead / maxVal) * plotH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Labels
    ctx.fillStyle = '#94a3b8';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'center';
    const labelStep = Math.max(1, Math.floor(data.length / 5));
    data.forEach((s, i) => {
      if (i % labelStep === 0) {
        const x = padding.left + i * xStep;
        ctx.fillText(new Date(s.started_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }), x, h - 5);
      }
    });

    // Legend
    ctx.fillStyle = '#22c55e'; ctx.fillRect(w - 120, 5, 12, 12);
    ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText('Alive', w - 104, 15);
    ctx.fillStyle = '#ef4444'; ctx.fillRect(w - 60, 5, 12, 12);
    ctx.fillStyle = '#94a3b8'; ctx.fillText('Dead', w - 44, 15);
  },

  // ─── Record Detail Drawer ───
  async portScanRecord(recordId) {
    try {
      this.toast('Full port scan started...', 'info');
      const result = await this.api(`/records/${recordId}/port-scan`, { method: 'POST' });
      this.toast(`Port scan complete: ${result.portsOpen.length} open ports found`, 'success');
      // Refresh the detail view
      this.closeDrawer();
      const domainId = this._currentDomain?.id;
      if (domainId) {
        this._currentRecords = await this.api(`/domains/${domainId}/records`);
        this.renderRecordsTable();
      }
      this.showRecordDetail(recordId);
    } catch (e) {
      this.toast(`Port scan failed: ${e.message}`, 'error');
    }
  },

  async setHealthCheckPort(recordId) {
    const input = document.getElementById('health-check-port-input');
    const port = parseInt(input?.value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      this.toast('Enter a valid port (1-65535)', 'error');
      return;
    }
    try {
      await this.api(`/records/${recordId}/health-port`, { method: 'PUT', body: { port } });
      this.toast(`Health check port set to ${port}`, 'success');
      this.closeDrawer();
      const domainId = this._currentDomain?.id;
      if (domainId) {
        this._currentRecords = await this.api(`/domains/${domainId}/records`);
        this.renderRecordsTable();
      }
      this.showRecordDetail(recordId);
    } catch (e) {
      this.toast(`Failed to set port: ${e.message}`, 'error');
    }
  },

  async clearHealthCheckPort(recordId) {
    try {
      await this.api(`/records/${recordId}/health-port`, { method: 'PUT', body: { port: null } });
      this.toast('Health check port cleared — using default checks', 'success');
      this.closeDrawer();
      const domainId = this._currentDomain?.id;
      if (domainId) {
        this._currentRecords = await this.api(`/domains/${domainId}/records`);
        this.renderRecordsTable();
      }
      this.showRecordDetail(recordId);
    } catch (e) {
      this.toast(`Failed to clear port: ${e.message}`, 'error');
    }
  },

  async showRecordDetail(recordId) {
    const record = this._currentRecords?.find(r => r.id === recordId);
    if (!record) return;

    const domain = this._currentDomain;
    const fullName = record.name === '@' ? domain.domain : `${record.name}.${domain.domain}`;
    const h = record.latest_health || {};

    let drawerHtml = `
      <div class="drawer-header">
        <h3>${this.esc(record.record_type)} Record: ${this.esc(fullName)}</h3>
        <button class="btn-icon" onclick="App.closeDrawer()">&#10005;</button>
      </div>
      <div class="drawer-body">
        <div class="drawer-section">
          <h4>Record Info</h4>
          <div class="drawer-row"><span class="label">Value</span><span class="value-text">${this.esc(record.value)}</span></div>
          <div class="drawer-row"><span class="label">TTL</span><span>${record.ttl || '-'}</span></div>
          ${record.priority ? `<div class="drawer-row"><span class="label">Priority</span><span>${record.priority}</span></div>` : ''}
          <div class="drawer-row"><span class="label">First Seen</span><span>${this.formatDate(record.first_seen)}</span></div>
          <div class="drawer-row"><span class="label">Last Seen</span><span>${this.formatDate(record.last_seen)}</span></div>
        </div>

        <div class="drawer-section">
          <h4>Health Status</h4>
          <div class="drawer-row"><span class="label">Status</span><span class="status-badge ${h.status || 'unknown'}">${(h.status || 'unknown').replace('_', ' ')}</span></div>
          ${h.check_method ? `<div class="drawer-row"><span class="label">Check Method</span><span>${this.esc(h.check_method)}</span></div>` : ''}
          ${h.response_ms ? `<div class="drawer-row"><span class="label">Response Time</span><span>${h.response_ms}ms</span></div>` : ''}
          ${h.error_message ? `<div class="drawer-row"><span class="label">Error</span><span style="color:var(--status-dead)">${this.esc(h.error_message)}</span></div>` : ''}
          ${h.status_code ? `<div class="drawer-row"><span class="label">HTTP Status</span><span>${h.status_code}</span></div>` : ''}
        </div>
    `;

    // Ports
    const ports = h.ports_open || [];
    const knownPorts = record.known_ports || [];
    const portNames = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',111:'RPCBind',135:'MSRPC',139:'NetBIOS',143:'IMAP',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',514:'Syslog',587:'Submission',636:'LDAPS',993:'IMAPS',995:'POP3S',1433:'MSSQL',1521:'Oracle',2049:'NFS',2082:'cPanel',2083:'cPanel SSL',2086:'WHM',2087:'WHM SSL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',5985:'WinRM',6379:'Redis',6443:'K8s API',8000:'HTTP Alt',8080:'HTTP Proxy',8443:'HTTPS Alt',8888:'HTTP Alt2',9090:'Prometheus',9200:'Elasticsearch',9443:'HTTPS Alt2',27017:'MongoDB'};
    if (!['TXT', 'CAA', 'SOA'].includes(record.record_type)) {
      const displayPorts = knownPorts.length > 0 ? knownPorts : [443, 80, 22, 8443, 8080, 3389, 21];
      drawerHtml += `<div class="drawer-section"><h4>Open Ports ${record.last_port_scan ? `<span style="font-weight:normal;font-size:12px;color:var(--text-muted)">(scanned ${this.timeAgo(record.last_port_scan)})</span>` : ''}</h4><div class="port-list">`;
      for (const p of displayPorts) {
        const open = ports.includes(p);
        const name = portNames[p] || p;
        drawerHtml += `<span class="port-badge ${open ? 'open' : 'closed'}">${name} (${p}) ${open ? '&#10004;' : '&#10008;'}</span>`;
      }
      drawerHtml += `</div><button class="btn-sm btn-secondary" style="margin-top:8px" onclick="App.portScanRecord(${record.id})">Rescan All Ports</button>
        <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
          <h4 style="margin:0 0 8px">Custom Health Check Port</h4>
          ${record.health_check_port
            ? `<div style="margin-bottom:8px"><span style="font-size:13px">Currently set to <strong>${record.health_check_port}</strong> — only this port is checked during scans.</span>
               <a href="#" style="font-size:13px;margin-left:8px" onclick="event.preventDefault();App.clearHealthCheckPort(${record.id})">Clear</a></div>`
            : `<div style="margin-bottom:8px;font-size:13px;color:var(--text-muted)">No custom port set — using default health checks.</div>`}
          <div style="display:flex;align-items:center;gap:8px">
            <input id="health-check-port-input" type="number" min="1" max="65535" placeholder="Port #" value="${record.health_check_port || ''}"
              style="width:90px;padding:4px 8px;border:1px solid var(--border);border-radius:4px;background:var(--bg-card);color:var(--text)"
              onkeydown="if(event.key==='Enter')App.setHealthCheckPort(${record.id})">
            <button class="btn-sm btn-secondary" onclick="App.setHealthCheckPort(${record.id})">Set Port</button>
          </div>
        </div>
      </div>`;
    }

    // SSL
    if (h.ssl_valid !== null && h.ssl_valid !== undefined) {
      drawerHtml += `<div class="drawer-section"><h4>SSL Certificate</h4>
        <div class="drawer-row"><span class="label">Valid</span><span style="color:${h.ssl_valid ? 'var(--status-alive)' : 'var(--status-dead)'}">${h.ssl_valid ? 'Yes' : 'No'}</span></div>
        ${h.ssl_expires_at ? `<div class="drawer-row"><span class="label">Expires</span><span>${new Date(h.ssl_expires_at).toLocaleDateString()}</span></div>` : ''}
        ${h.ssl_error ? `<div class="drawer-row"><span class="label">Error</span><span>${this.esc(h.ssl_error)}</span></div>` : ''}
      </div>`;
    }

    // Propagation
    if (h.propagation_results) {
      const prop = typeof h.propagation_results === 'string' ? JSON.parse(h.propagation_results) : h.propagation_results;
      drawerHtml += `<div class="drawer-section"><h4>DNS Propagation ${prop.consistent ? '<span style="color:var(--status-alive)">(Consistent)</span>' : '<span style="color:var(--status-warning)">(Inconsistent)</span>'}</h4>`;
      for (const r of (prop.resolvers || [])) {
        const cls = r.error ? 'error' : (prop.consistent ? 'match' : 'mismatch');
        drawerHtml += `<div class="prop-row"><span class="prop-dot ${cls}"></span><strong>${this.esc(r.name)}</strong> (${r.server}): ${r.error ? `<span style="color:var(--status-dead)">${r.error}</span>` : this.esc(r.values?.join(', ') || '-')}</div>`;
      }
      drawerHtml += `</div>`;
    }

    // WHOIS in drawer
    if (domain) {
      try {
        const whois = await this.api(`/domains/${domain.id}/whois`).catch(() => null);
        if (whois && whois.registrar) {
          drawerHtml += `<div class="drawer-section"><h4>WHOIS Info</h4>
            ${whois.registrar ? `<div class="drawer-row"><span class="label">Registrar</span><span>${this.esc(whois.registrar)}</span></div>` : ''}
            ${whois.expiry_date ? `<div class="drawer-row"><span class="label">Expires</span><span>${new Date(whois.expiry_date).toLocaleDateString()}</span></div>` : ''}
            ${whois.name_servers ? `<div class="drawer-row"><span class="label">Nameservers</span><span>${this.esc(Array.isArray(whois.name_servers) ? whois.name_servers.join(', ') : whois.name_servers)}</span></div>` : ''}
          </div>`;
        }
      } catch (e) {}
    }

    // Health history
    try {
      const history = await this.api(`/records/${recordId}/history`);
      if (history.length > 0) {
        drawerHtml += `<div class="drawer-section"><h4>Health History</h4><div class="health-timeline">`;
        for (const hc of history.slice(0, 30).reverse()) {
          drawerHtml += `<div class="health-block ${hc.status}" data-tooltip="${this.formatDate(hc.checked_at)} - ${hc.status}"></div>`;
        }
        drawerHtml += `</div></div>`;
      }
    } catch (e) {}

    // Changes
    try {
      const changes = await this.api(`/records/${recordId}/changes`);
      if (changes.length > 0) {
        drawerHtml += `<div class="drawer-section"><h4>Change History</h4>`;
        for (const c of changes.slice(0, 10)) {
          drawerHtml += `<div style="padding:6px 0;border-bottom:1px solid var(--border-subtle);font-size:13px">
            <div style="color:var(--text-muted)">${this.formatDate(c.changed_at)}</div>
            <div><span class="value-text">${this.esc(c.old_value)}</span> &rarr; <span class="value-text">${this.esc(c.new_value)}</span></div>
          </div>`;
        }
        drawerHtml += `</div>`;
      }
    } catch (e) {}

    drawerHtml += `
        <div style="margin-top:20px">
          <button class="btn-secondary" onclick="App.dismissRecord(${record.id}, ${record.dismissed ? 'false' : 'true'}); App.closeDrawer();">${record.dismissed ? 'Undismiss' : 'Dismiss Record'}</button>
        </div>
      </div>`;

    const drawer = document.getElementById('drawer');
    const overlay = document.getElementById('modal-overlay');
    drawer.innerHTML = drawerHtml;
    drawer.classList.remove('hidden');
    requestAnimationFrame(() => drawer.classList.add('open'));
    overlay.classList.remove('hidden');
    overlay.style.display = '';
    overlay.onclick = () => App.closeDrawer();
  },
});
