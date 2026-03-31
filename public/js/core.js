'use strict';

const App = {
  user: null,
  currentRoute: '',
  eventSource: null,
  scanningDomains: new Set(),
  selectedDomains: new Set(),

  // ─── API Client ───
  async api(path, opts = {}) {
    const res = await fetch(`/api${path}`, {
      headers: { 'Content-Type': 'application/json', ...opts.headers },
      ...opts,
      body: opts.body && typeof opts.body !== 'string' ? JSON.stringify(opts.body) : opts.body,
    });
    if (res.status === 401 && !path.includes('/auth/')) {
      this.user = null;
      this.navigate('login');
      throw new Error('Session expired');
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(err.error || 'Request failed');
    }
    const ct = res.headers.get('content-type');
    if (ct && ct.includes('json')) return res.json();
    return res.text();
  },

  // ─── Toast ───
  toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 5000);
  },

  // ─── Navigation ───
  navigate(route) {
    window.location.hash = route;
  },

  async init() {
    this.initTheme();
    window.addEventListener('hashchange', () => this.route());
    try {
      this.user = await this.api('/auth/me');
      this.connectSSE();
    } catch (e) {
      this.user = null;
    }
    this.route();
  },

  // ─── Theme ───
  initTheme() {
    const saved = localStorage.getItem('theme') || 'auto';
    this.applyTheme(saved);
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if (localStorage.getItem('theme') === 'auto') this.applyTheme('auto');
    });
  },

  applyTheme(theme) {
    localStorage.setItem('theme', theme);
    if (theme === 'auto') {
      const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    } else {
      document.documentElement.setAttribute('data-theme', theme);
    }
  },

  cycleTheme() {
    const current = localStorage.getItem('theme') || 'auto';
    const next = current === 'auto' ? 'light' : current === 'light' ? 'dark' : 'auto';
    this.applyTheme(next);
    this.toast(`Theme: ${next}`, 'info');
    // Update the theme icon
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.innerHTML = this.getThemeIcon();
  },

  getThemeIcon() {
    const theme = localStorage.getItem('theme') || 'auto';
    if (theme === 'dark') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    if (theme === 'light') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>';
  },

  async route() {
    const hash = window.location.hash.slice(1) || 'dashboard';
    const parts = hash.split('/');
    this.currentRoute = parts[0];

    const publicRoutes = ['login', 'register', 'forgot-password', 'reset-password', 'accept-invite'];
    if (!this.user && !publicRoutes.includes(parts[0])) {
      return this.navigate('login');
    }
    if (this.user && publicRoutes.includes(parts[0])) {
      return this.navigate('dashboard');
    }

    this.closeDrawer();

    switch (parts[0]) {
      case 'login': this.renderLogin(); break;
      case 'register': this.renderRegister(); break;
      case 'forgot-password': this.renderForgotPassword(); break;
      case 'reset-password': this.renderResetPassword(parts[1]); break;
      case 'accept-invite': this.renderAcceptInvite(parts[1]); break;
      case 'dashboard': this.renderDashboard(); break;
      case 'domains': parts[1] ? this.renderDomainDetail(parts[1]) : this.renderDomains(); break;
      case 'settings': this.renderSettings(); break;
      default: this.navigate('dashboard');
    }
  },

  // ─── SSE ───
  connectSSE() {
    if (this.eventSource) this.eventSource.close();
    this.eventSource = new EventSource('/api/events');
    this.eventSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === 'scan_completed') {
          this.scanningDomains.delete(data.domainId);
          this.updateScanProgress(data.domainId, null);
          this.toast(`Scan complete: ${data.alive} alive, ${data.dead} dead`, data.dead > 0 ? 'warning' : 'success');
          if (this.currentRoute === 'dashboard') this.renderDashboard();
          if (this.currentRoute === 'domains') this.route();
        } else if (data.type === 'scan_started') {
          this.scanningDomains.add(data.domainId);
          this.updateScanProgress(data.domainId, { phase: 'starting', checked: 0, total: 0 });
        } else if (data.type === 'scan_progress') {
          this.updateScanProgress(data.domainId, data);
        } else if (data.type === 'scan_failed') {
          this.scanningDomains.delete(data.domainId);
          this.updateScanProgress(data.domainId, null);
          this.toast(`Scan failed: ${data.error}`, 'error');
        }
      } catch (e) {}
    };
  },

  updateScanProgress(domainId, data) {
    // Update all progress bars for this domain
    const bars = document.querySelectorAll(`.scan-progress[data-domain-id="${domainId}"]`);
    bars.forEach(bar => {
      if (!data) {
        bar.remove();
        return;
      }
      const pct = data.total > 0 ? Math.round((data.checked / data.total) * 100) : 0;
      const label = data.phase === 'enumerating' ? 'Discovering records...'
        : data.phase === 'starting' ? 'Starting scan...'
        : `Checking ${data.checked}/${data.total} records`;
      bar.querySelector('.progress-fill').style.width = `${pct}%`;
      bar.querySelector('.progress-label').textContent = label;
    });
    // Create progress bar on domain cards if not present
    if (data && !bars.length) {
      const card = document.querySelector(`.domain-card[data-id="${domainId}"], .page-header`);
      if (card) {
        const existing = card.querySelector('.scan-progress');
        if (!existing) {
          const el = document.createElement('div');
          el.className = 'scan-progress';
          el.dataset.domainId = domainId;
          el.innerHTML = `<div class="progress-track"><div class="progress-fill" style="width:0%"></div></div><div class="progress-label">Starting scan...</div>`;
          card.appendChild(el);
        }
      }
    }
  },

  // ─── Layout ───
  renderLayout(content, breadcrumbs = '') {
    const app = document.getElementById('app');
    const isAdmin = this.user?.role === 'admin';
    const icons = {
      dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
      domains: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
      settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    };

    app.innerHTML = `
      <div class="app-layout">
        <aside class="sidebar">
          <div class="sidebar-header">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
            <h1>DNS Scanner</h1>
          </div>
          <nav class="sidebar-nav">
            <a href="#dashboard" class="${this.currentRoute === 'dashboard' ? 'active' : ''}">${icons.dashboard}<span>Dashboard</span></a>
            <a href="#domains" class="${this.currentRoute === 'domains' ? 'active' : ''}">${icons.domains}<span>Domains</span></a>
            <a href="#settings" class="${this.currentRoute === 'settings' ? 'active' : ''}">${icons.settings}<span>Settings</span></a>
          </nav>
          <div class="sidebar-footer">
            <div style="margin-bottom:4px">${this.esc(this.user.username)} (${this.esc(this.user.role)})</div>
            <div style="display:flex;gap:8px;align-items:center">
              <button id="theme-toggle" class="btn-icon" onclick="App.cycleTheme()" title="Toggle theme" style="padding:2px">${this.getThemeIcon()}</button>
              <a href="#" onclick="App.logout();return false">Sign out</a>
            </div>
            <div style="display:flex;gap:12px;align-items:center;margin-top:8px;font-size:0.85em">
              <a href="https://github.com/djlactose/DNS-Scanner" target="_blank" rel="noopener noreferrer" title="Source Code" style="display:flex;align-items:center;gap:4px">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
                Source
              </a>
              <a href="https://buymeacoffee.com/djlactose" target="_blank" rel="noopener noreferrer" title="Buy Me a Coffee" style="display:flex;align-items:center;gap:4px">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M20.216 6.415l-.132-.666c-.119-.598-.388-1.163-1.001-1.379-.197-.069-.42-.098-.57-.241-.152-.143-.196-.366-.231-.572-.065-.378-.125-.756-.192-1.133-.057-.325-.102-.69-.25-.987-.195-.4-.597-.634-.996-.788a5.723 5.723 0 00-.626-.194c-1-.263-2.05-.36-3.077-.416a25.834 25.834 0 00-3.7.062c-.915.083-1.88.184-2.75.5-.318.116-.646.256-.888.501-.297.302-.393.77-.177 1.146.154.267.415.456.692.58.36.162.737.284 1.123.366 1.075.238 2.189.331 3.287.37 1.218.05 2.437.01 3.65-.118.299-.033.598-.073.896-.119.352-.054.578-.513.474-.834-.124-.383-.457-.531-.834-.473-.466.074-.96.108-1.382.146-1.177.08-2.358.082-3.536.006a22.228 22.228 0 01-1.157-.107c-.086-.01-.18-.025-.258-.036-.243-.036-.484-.08-.724-.13-.111-.027-.111-.185 0-.212h.005c.277-.06.557-.108.838-.147h.002c.131-.009.263-.032.394-.048a25.076 25.076 0 013.426-.12c.674.019 1.347.062 2.014.13l.04.005c.23.029.46.06.692.095.088.013.176.03.265.042.087.013.184.028.282.038.246.028.42-.121.46-.349.044-.245-.1-.469-.348-.507l-.145-.024a24.968 24.968 0 00-4.381-.378c-1.026.015-2.057.09-3.07.283-.14.027-.282.056-.422.089-.135.032-.281.07-.424.113-.279.085-.558.205-.793.397-.293.239-.483.605-.492.997-.015.627.37 1.237.916 1.492.312.147.658.2 1 .213.392.015.784-.003 1.175-.038.812-.074 1.62-.194 2.416-.381a21.5 21.5 0 001.29-.346c.164-.05.318-.133.457-.236.28-.21.423-.554.323-.889l.001.002zM7.5 12.5c0 .552-.448 1-1 1s-1-.448-1-1 .448-1 1-1 1 .448 1 1zm9 0c0 .552-.448 1-1 1s-1-.448-1-1 .448-1 1-1 1 .448 1 1zM12 17c-1.105 0-2-.672-2-1.5S10.895 14 12 14s2 .672 2 1.5S13.105 17 12 17z"/><path d="M20 10H4a1 1 0 00-1 1v1c0 4.97 3.582 9.128 8.5 9.876V24h1v-2.124C17.418 21.128 21 16.97 21 12v-1a1 1 0 00-1-1zm-1 2c0 3.86-3.14 7-7 7s-7-3.14-7-7v0h14z"/></svg>
                Coffee
              </a>
            </div>
          </div>
        </aside>
        <main class="main-content">
          ${breadcrumbs ? `<div class="breadcrumbs">${breadcrumbs}</div>` : ''}
          ${content}
        </main>
        <nav class="bottom-nav">
          <a href="#dashboard" class="${this.currentRoute === 'dashboard' ? 'active' : ''}">${icons.dashboard}Dashboard</a>
          <a href="#domains" class="${this.currentRoute === 'domains' ? 'active' : ''}">${icons.domains}Domains</a>
          <a href="#settings" class="${this.currentRoute === 'settings' ? 'active' : ''}">${icons.settings}Settings</a>
        </nav>
      </div>`;
  },

  // ─── Utilities ───
  esc(str) { const d = document.createElement('div'); d.textContent = str || ''; return d.innerHTML; },

  timeAgo(date) {
    if (!date) return 'Never';
    const s = Math.floor((Date.now() - new Date(date)) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  },

  formatDate(d) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  },

  // ─── WebAuthn Helpers ───
  bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  },

  base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const str = atob(base64);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
  },

  urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    return Uint8Array.from([...rawData].map(char => char.charCodeAt(0)));
  },

  // ─── Modal ───
  showModal(title, body, onConfirm, confirmText = 'Save') {
    const overlay = document.getElementById('modal-overlay');
    overlay.classList.remove('hidden');
    overlay.innerHTML = `<div class="modal">
      <h3>${title}</h3>
      ${body}
      <div class="form-actions">
        <button class="btn-secondary" onclick="App.closeModal()">Cancel</button>
        <button class="btn-primary" id="modal-confirm">${confirmText}</button>
      </div>
      <div id="modal-error" class="form-error" style="display:none;margin-top:8px"></div>
    </div>`;
    overlay.querySelector('.modal').onclick = (e) => e.stopPropagation();
    overlay.onclick = () => this.closeModal();
    document.getElementById('modal-confirm').onclick = async () => {
      try {
        await onConfirm();
        this.closeModal();
      } catch (e) {
        const errEl = document.getElementById('modal-error');
        if (errEl) { errEl.textContent = e.message; errEl.style.display = 'block'; }
      }
    };
  },

  closeModal() {
    document.getElementById('modal-overlay').classList.add('hidden');
    document.getElementById('modal-overlay').innerHTML = '';
  },

  // ─── Drawer ───
  openDrawer(content) {
    const drawer = document.getElementById('drawer');
    drawer.classList.remove('hidden');
    drawer.innerHTML = content;
    requestAnimationFrame(() => drawer.classList.add('open'));
  },

  closeDrawer() {
    const drawer = document.getElementById('drawer');
    const overlay = document.getElementById('modal-overlay');
    drawer.classList.remove('open');
    if (overlay) { overlay.classList.add('hidden'); overlay.style.display = 'none'; overlay.onclick = null; }
    setTimeout(() => { drawer.classList.add('hidden'); drawer.innerHTML = ''; }, 250);
  },

  async logout() {
    await this.api('/auth/logout', { method: 'POST' }).catch(() => {});
    this.user = null;
    if (this.eventSource) this.eventSource.close();
    this.navigate('login');
  },
};
