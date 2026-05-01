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
        <div class="stat-card card clickable" role="link" tabindex="0" onclick="App.navigate('domains')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.navigate('domains')}" aria-label="View all monitored domains"><div class="stat-value">${data.total_domains}</div><div class="stat-label">Domains Monitored</div></div>
        <div class="stat-card card clickable" role="link" tabindex="0" onclick="App.navigate('domains?status=healthy')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.navigate('domains?status=healthy')}" aria-label="View healthy domains"><div class="stat-value" style="color:var(--status-alive)">${data.alive_records}</div><div class="stat-label">Alive Records</div></div>
        <div class="stat-card card clickable ${deadCount > 0 ? 'dead' : ''}" role="link" tabindex="0" onclick="App.navigate('domains?status=dead')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.navigate('domains?status=dead')}" aria-label="View domains with dead records"><div class="stat-value">${deadCount}</div><div class="stat-label">Dead Records</div></div>
        ${data.expiring_certs && data.expiring_certs.length > 0 ? `<div class="stat-card card clickable" role="link" tabindex="0" onclick="document.getElementById('expiring-certs-section')?.scrollIntoView({behavior:'smooth'})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();document.getElementById('expiring-certs-section')?.scrollIntoView({behavior:'smooth'})}" aria-label="Jump to expiring certificates list"><div class="stat-value" style="color:var(--status-warning, orange)">${data.expiring_certs.length}</div><div class="stat-label">Expiring Certs</div></div>` : ''}
      </div>`;

      // Worker health indicator
      html += `<div id="worker-health" style="margin-bottom:16px"></div>`;

      // Cloudflare Tunnel health
      html += `<div id="tunnel-health" style="margin-bottom:16px"></div>`;

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
          // Clicking the card body opens the record-detail drawer in place;
          // explicit buttons stop propagation so they keep their own behavior.
          html += `<div class="alert-card clickable ${isTakeover ? 'takeover' : ''}" role="button" tabindex="0" onclick="App.showRecordDetail(${r.id})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.showRecordDetail(${r.id})}" aria-label="Open detail for ${this.esc(r.record_type)} record">
            <div class="alert-icon">${isTakeover ? '&#9888;' : '&#10060;'}</div>
            <div class="alert-body">
              <div class="alert-title">${this.esc(r.name === '@' ? r.domain : r.name + '.' + r.domain)} &middot; ${this.esc(r.record_type)} &middot; <span class="value-text">${this.esc(r.value)}</span></div>
              <div class="alert-detail">${isTakeover ? 'Potential subdomain takeover risk!' : this.esc(r.error_message || 'No response on any port')}</div>
              <div class="alert-actions">
                <button class="btn-sm btn-secondary" onclick="event.stopPropagation();App.navigate('domains/${r.domain_id}')">Open Domain</button>
                <button class="btn-sm btn-secondary" onclick="event.stopPropagation();App.dismissRecord(${r.id})">Dismiss</button>
              </div>
            </div>
          </div>`;
        }
      } else {
        html += `<div class="card" style="text-align:center;padding:30px;color:var(--status-alive)"><div style="font-size:32px">&#10004;</div><div style="margin-top:8px">All systems healthy</div></div>`;
      }

      if (data.expiring_certs && data.expiring_certs.length > 0) {
        html += `<div class="section-header" id="expiring-certs-section">Expiring SSL Certificates</div>`;
        for (const c of data.expiring_certs) {
          const daysUntil = Math.ceil((new Date(c.ssl_expires_at) - Date.now()) / 86400000);
          const urgency = daysUntil <= 7 ? 'var(--status-dead)' : daysUntil <= 14 ? 'var(--status-warning, orange)' : 'var(--accent)';
          const fqdn = c.name === '@' ? c.domain : `${c.name}.${c.domain}`;
          html += `<div class="alert-card clickable" role="button" tabindex="0" style="border-left-color:${urgency}" onclick="App.showRecordDetail(${c.id})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.showRecordDetail(${c.id})}" aria-label="Open detail for ${this.esc(fqdn)} certificate">
            <div class="alert-icon" style="color:${urgency}">&#128274;</div>
            <div class="alert-body">
              <div class="alert-title">${this.esc(fqdn)} &middot; ${this.esc(c.record_type)}</div>
              <div class="alert-detail">Certificate expires in ${daysUntil} day${daysUntil !== 1 ? 's' : ''} (${new Date(c.ssl_expires_at).toLocaleDateString()})</div>
              <div class="alert-actions">
                <button class="btn-sm btn-secondary" onclick="event.stopPropagation();App.navigate('domains/${c.domain_id}')">Open Domain</button>
              </div>
            </div>
          </div>`;
        }
      }

      if (data.recent_changes && data.recent_changes.length > 0) {
        html += `<div class="section-header">Recent DNS Changes</div>`;
        for (const c of data.recent_changes.slice(0, 10)) {
          // record_id may be null if the original record was deleted; only make
          // the row clickable when we have a target.
          const clickable = c.record_id ? `clickable" role="button" tabindex="0" onclick="App.showRecordDetail(${c.record_id})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.showRecordDetail(${c.record_id})}" aria-label="Open record detail` : '';
          html += `<div class="alert-card ${clickable}" style="border-left-color:var(--accent)">
            <div class="alert-icon" style="color:var(--accent)">&#8644;</div>
            <div class="alert-body">
              <div class="alert-title">${this.esc(c.record_type)} ${this.esc(c.name)}.${this.esc(c.domain)}</div>
              <div class="alert-detail"><span class="value-text">${this.esc(c.old_value)}</span> &rarr; <span class="value-text">${this.esc(c.new_value)}</span> &middot; ${this.timeAgo(c.changed_at)}</div>
            </div>
          </div>`;
        }
      }

      el.innerHTML = html;

      // Fetch worker health and tunnel status
      this.loadWorkerHealth();
      this.loadTunnelHealth();
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
      container.innerHTML = `<div class="card clickable" role="link" tabindex="0" style="display:flex;align-items:center;gap:12px;padding:12px 16px" onclick="App.navigate('settings')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.navigate('settings')}" aria-label="Open Settings">
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

  async loadTunnelHealth() {
    const container = document.getElementById('tunnel-health');
    if (!container) return;
    try {
      const data = await this.api('/tunnels/summary');
      if (!data || data.total === 0) return;
      let color = 'var(--status-alive)';
      const parts = [];
      if (data.healthy > 0) parts.push(`${data.healthy} healthy`);
      if (data.degraded > 0) parts.push(`${data.degraded} degraded`);
      if (data.down > 0) parts.push(`${data.down} down`);
      if (data.unknown > 0) parts.push(`${data.unknown} unknown`);
      if (data.down > 0) color = 'var(--status-dead)';
      else if (data.degraded > 0) color = 'var(--status-warning, orange)';
      else if (data.unknown > 0 && data.healthy === 0) color = 'var(--text-muted)';
      // The whole card navigates to the domains list. If at least one tunnel
      // is down, route to dead-records filter so the user lands on the actual
      // problem records faster.
      const target = data.down > 0 ? 'domains?status=dead' : 'domains';
      container.innerHTML = `<div class="card clickable" role="link" tabindex="0" style="display:flex;align-items:center;gap:12px;padding:12px 16px" onclick="App.navigate('${target}')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();App.navigate('${target}')}" aria-label="View tunnel-related records">
        <div style="width:10px;height:10px;border-radius:50%;background:${color}"></div>
        <div>
          <div style="font-weight:600;font-size:14px">Cloudflare Tunnels (${data.total})</div>
          <div style="font-size:12px;color:var(--text-muted)">${parts.join(', ')}</div>
        </div>
      </div>`;
    } catch (e) {
      // Tunnel endpoint may not exist yet, silently ignore
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
