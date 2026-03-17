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
          this.toast(`Scan complete: ${data.alive} alive, ${data.dead} dead`, data.dead > 0 ? 'warning' : 'success');
          if (this.currentRoute === 'dashboard') this.renderDashboard();
          if (this.currentRoute === 'domains') this.route();
        } else if (data.type === 'scan_started') {
          this.scanningDomains.add(data.domainId);
        } else if (data.type === 'scan_failed') {
          this.scanningDomains.delete(data.domainId);
          this.toast(`Scan failed: ${data.error}`, 'error');
        }
      } catch (e) {}
    };
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
    drawer.classList.remove('open');
    setTimeout(() => { drawer.classList.add('hidden'); drawer.innerHTML = ''; }, 250);
  },

  async logout() {
    await this.api('/auth/logout', { method: 'POST' }).catch(() => {});
    this.user = null;
    if (this.eventSource) this.eventSource.close();
    this.navigate('login');
  },
};
