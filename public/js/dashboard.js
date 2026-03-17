Object.assign(App, {
  async renderDashboard() {
    const isAdmin = this.user?.role === 'admin';
    this.renderLayout(`
      <div class="page-header"><h2>Dashboard</h2>
        <div style="display:flex;gap:8px">
          ${isAdmin ? '<button class="btn-primary" onclick="App.showAddDomain()">+ Add Domain</button>' : ''}
          <button class="btn-secondary" onclick="App.scanAll()">Scan All Now</button>
        </div>
      </div>
      <div id="dashboard-content"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div>
    `);
    try {
      const data = await this.api('/dashboard');
      const deadCount = data.dead_records.length;
      const el = document.getElementById('dashboard-content');
      if (!el) return;

      if (data.total_domains === 0) {
        el.innerHTML = `<div class="empty-state"><div class="empty-icon">&#127760;</div><h3>No domains configured</h3><p>Add your first domain to start monitoring DNS records.</p>
          ${isAdmin ? '<button class="btn-primary" onclick="App.showAddDomain()">+ Add Domain</button>' : '<p>Ask an admin to add domains.</p>'}</div>`;
        return;
      }

      let html = `<div class="card-grid">
        <div class="stat-card card"><div class="stat-value">${data.total_domains}</div><div class="stat-label">Domains Monitored</div></div>
        <div class="stat-card card"><div class="stat-value" style="color:var(--status-alive)">${data.alive_records}</div><div class="stat-label">Alive Records</div></div>
        <div class="stat-card card ${deadCount > 0 ? 'dead' : ''}"><div class="stat-value">${deadCount}</div><div class="stat-label">Dead Records</div></div>
      </div>`;

      // Worker health indicator
      html += `<div id="worker-health" style="margin-bottom:16px"></div>`;

      // IPv6 connectivity warning
      if (data.ipv6_available === false) {
        html += `<div class="card" style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-left:4px solid var(--status-warning);margin-bottom:16px">
          <div style="font-size:18px">&#9888;</div>
          <div>
            <div style="font-weight:600;font-size:14px">IPv6 Unavailable</div>
            <div style="font-size:12px;color:var(--text-secondary)">This host lacks IPv6 connectivity. AAAA record health checks are skipped and shown as &quot;No IPv6&quot; instead.</div>
          </div>
        </div>`;
      }

      if (deadCount > 0) {
        html += `<div class="section-header">Dead Records Requiring Attention</div>`;
        for (const r of data.dead_records) {
          const isTakeover = r.status === 'takeover_risk';
          html += `<div class="alert-card ${isTakeover ? 'takeover' : ''}">
            <div class="alert-icon">${isTakeover ? '&#9888;' : '&#10060;'}</div>
            <div class="alert-body">
              <div class="alert-title">${this.esc(r.name === '@' ? r.domain : r.name + '.' + r.domain)} &middot; ${this.esc(r.record_type)} &middot; <span class="value-text">${this.esc(r.value)}</span></div>
              <div class="alert-detail">${isTakeover ? 'Potential subdomain takeover risk!' : this.esc(r.error_message || 'No response on any port')}</div>
              <div class="alert-actions">
                <button class="btn-sm btn-secondary" onclick="App.navigate('domains/${r.domain_id}')">View</button>
                <button class="btn-sm btn-secondary" onclick="App.dismissRecord(${r.id})">Dismiss</button>
              </div>
            </div>
          </div>`;
        }
      } else {
        html += `<div class="card" style="text-align:center;padding:30px;color:var(--status-alive)"><div style="font-size:32px">&#10004;</div><div style="margin-top:8px">All systems healthy</div></div>`;
      }

      if (data.recent_changes && data.recent_changes.length > 0) {
        html += `<div class="section-header">Recent DNS Changes</div>`;
        for (const c of data.recent_changes.slice(0, 10)) {
          html += `<div class="alert-card" style="border-left-color:var(--accent)">
            <div class="alert-icon" style="color:var(--accent)">&#8644;</div>
            <div class="alert-body">
              <div class="alert-title">${this.esc(c.record_type)} ${this.esc(c.name)}.${this.esc(c.domain)}</div>
              <div class="alert-detail"><span class="value-text">${this.esc(c.old_value)}</span> &rarr; <span class="value-text">${this.esc(c.new_value)}</span> &middot; ${this.timeAgo(c.changed_at)}</div>
            </div>
          </div>`;
        }
      }

      el.innerHTML = html;

      // Fetch worker health
      this.loadWorkerHealth();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async loadWorkerHealth() {
    const container = document.getElementById('worker-health');
    if (!container) return;
    try {
      const status = await this.api('/settings/worker/status');
      let color = 'var(--status-alive)';
      let label = 'Healthy';
      if (status.stale) {
        color = status.staleness_seconds > 300 ? 'var(--status-dead)' : 'var(--status-warning, orange)';
        label = status.staleness_seconds > 300 ? 'Offline' : 'Stale';
      }
      container.innerHTML = `<div class="card" style="display:flex;align-items:center;gap:12px;padding:12px 16px">
        <div style="width:10px;height:10px;border-radius:50%;background:${color}"></div>
        <div>
          <div style="font-weight:600;font-size:14px">Worker ${label}</div>
          <div style="font-size:12px;color:var(--text-muted)">Last heartbeat: ${status.last_heartbeat ? this.timeAgo(status.last_heartbeat) : 'Never'}</div>
        </div>
      </div>`;
    } catch (e) {
      // Worker status endpoint may not exist, silently ignore
    }
  },

  async scanAll() {
    try {
      const result = await this.api('/scan-all', { method: 'POST' });
      this.toast(`Started scanning ${result.started} domain(s)`, 'info');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async dismissRecord(id, dismissed) {
    try {
      await this.api(`/records/${id}/dismiss`, { method: 'PUT', body: { dismissed: dismissed !== false } });
      this.toast(dismissed === false ? 'Record undismissed' : 'Record dismissed', 'success');
      if (this.currentRoute === 'dashboard') this.renderDashboard();
    } catch (e) { this.toast(e.message, 'error'); }
  },
});
