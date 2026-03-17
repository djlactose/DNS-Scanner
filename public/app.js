'use strict';

const App = {
  user: null,
  currentRoute: '',
  eventSource: null,
  scanningDomains: new Set(),

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
    window.addEventListener('hashchange', () => this.route());
    try {
      this.user = await this.api('/auth/me');
      this.connectSSE();
    } catch (e) {
      this.user = null;
    }
    this.route();
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
            <a href="#" onclick="App.logout(); return false;">Sign out</a>
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
      </div>
    `;
  },

  esc(str) { const d = document.createElement('div'); d.textContent = str || ''; return d.innerHTML; },
  timeAgo(date) {
    if (!date) return 'Never';
    const s = Math.floor((Date.now() - new Date(date)) / 1000);
    if (s < 60) return 'Just now';
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    if (s < 86400) return `${Math.floor(s/3600)}h ago`;
    return `${Math.floor(s/86400)}d ago`;
  },
  formatDate(date) { return date ? new Date(date).toLocaleString() : '-'; },

  // ─── WebAuthn helpers ───
  bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const str = atob(base64);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
  },

  // ─── Auth ───
  async renderLogin() {
    // Check Google auth status
    let googleEnabled = false;
    try {
      const gs = await fetch('/api/auth/google/status').then(r => r.json());
      googleEnabled = gs.enabled;
    } catch (e) {}
    const hasWebAuthn = !!window.PublicKeyCredential;

    let altLogins = '';
    if (hasWebAuthn || googleEnabled) {
      altLogins = '<div class="auth-divider"><span>or</span></div>';
      if (hasWebAuthn) altLogins += '<button class="btn-secondary btn-passkey" onclick="App.doPasskeyLogin()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><circle cx="12" cy="16.5" r="1.5"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Sign in with Passkey</button>';
      if (googleEnabled) altLogins += '<button class="btn-secondary btn-google" onclick="window.location.href=\'/api/auth/google\'"><svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#34A853" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#FBBC05" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg> Sign in with Google</button>';
    }

    const errorParam = new URLSearchParams(window.location.hash.split('?')[1] || '');
    const errorMsg = errorParam.get('error');
    const errorMap = { google_auth_failed: 'Google sign-in failed', google_token_failed: 'Google authentication error', first_user_must_register: 'First user must register with a password' };

    document.getElementById('app').innerHTML = `
      <div class="auth-page"><div class="auth-card card">
        <h1>DNS Scanner</h1><p>Sign in to continue</p>
        <div class="form-group"><label>Username</label><input id="login-user" autocomplete="username"></div>
        <div class="form-group"><label>Password</label><input id="login-pass" type="password" autocomplete="current-password"></div>
        <div id="login-error" class="form-error" style="display:${errorMsg ? 'block' : 'none'}">${errorMsg ? (errorMap[errorMsg] || errorMsg) : ''}</div>
        <button class="btn-primary" onclick="App.doLogin()">Sign In</button>
        <div class="auth-switch"><a href="#forgot-password">Forgot password?</a></div>
        ${altLogins}
        <div class="auth-switch">Don't have an account? <a href="#register">Register</a></div>
      </div></div>`;
    document.getElementById('login-user').focus();
    document.getElementById('login-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') App.doLogin(); });
  },

  renderRegister() {
    document.getElementById('app').innerHTML = `
      <div class="auth-page"><div class="auth-card card">
        <h1>Create Account</h1><p>First user becomes admin</p>
        <div class="form-group"><label>Username</label><input id="reg-user" autocomplete="username"></div>
        <div class="form-group"><label>Email (optional)</label><input id="reg-email" type="email"></div>
        <div class="form-group"><label>Password (min 8 chars)</label><input id="reg-pass" type="password" autocomplete="new-password"></div>
        <div id="reg-error" class="form-error" style="display:none"></div>
        <button class="btn-primary" onclick="App.doRegister()">Register</button>
        <div class="auth-switch">Already have an account? <a href="#login">Sign in</a></div>
      </div></div>`;
  },

  async doLogin() {
    const errEl = document.getElementById('login-error');
    try {
      errEl.style.display = 'none';
      const result = await this.api('/auth/login', { method: 'POST', body: { username: document.getElementById('login-user').value, password: document.getElementById('login-pass').value } });
      if (result.requires2fa) {
        this.show2faPrompt();
        return;
      }
      this.user = result;
      this.connectSSE();
      this.navigate('dashboard');
    } catch (e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  },

  show2faPrompt() {
    document.getElementById('app').innerHTML = `
      <div class="auth-page"><div class="auth-card card">
        <h1>Two-Factor Authentication</h1>
        <p>Verify your identity with a passkey</p>
        <div id="2fa-error" class="form-error" style="display:none"></div>
        <button class="btn-primary btn-passkey" onclick="App.doPasskey2fa()">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><circle cx="12" cy="16.5" r="1.5"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
          Verify with Passkey
        </button>
        <div class="auth-switch"><a href="#login" onclick="App.user=null">Cancel</a></div>
      </div></div>`;
  },

  async doPasskey2fa() {
    const errEl = document.getElementById('2fa-error');
    try {
      if (errEl) errEl.style.display = 'none';
      const options = await this.api('/auth/passkey/2fa-options', { method: 'POST' });
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: this.base64urlToBuffer(c.id) }));
      }
      options.challenge = this.base64urlToBuffer(options.challenge);
      const assertion = await navigator.credentials.get({ publicKey: options });
      const result = await this.api('/auth/passkey/verify-2fa', { method: 'POST', body: {
        credential: {
          id: assertion.id,
          rawId: this.bufferToBase64url(assertion.rawId),
          type: assertion.type,
          response: {
            authenticatorData: this.bufferToBase64url(assertion.response.authenticatorData),
            clientDataJSON: this.bufferToBase64url(assertion.response.clientDataJSON),
            signature: this.bufferToBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle ? this.bufferToBase64url(assertion.response.userHandle) : undefined,
          },
        },
      }});
      this.user = result;
      this.connectSSE();
      this.navigate('dashboard');
    } catch (e) {
      if (errEl) { errEl.textContent = e.message || 'Passkey verification failed'; errEl.style.display = 'block'; }
    }
  },

  async doPasskeyLogin() {
    const errEl = document.getElementById('login-error');
    try {
      if (errEl) errEl.style.display = 'none';
      const options = await this.api('/auth/passkey/login-options', { method: 'POST', body: {} });
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: this.base64urlToBuffer(c.id) }));
      }
      options.challenge = this.base64urlToBuffer(options.challenge);
      const assertion = await navigator.credentials.get({ publicKey: options });
      const result = await this.api('/auth/passkey/login-verify', { method: 'POST', body: {
        credential: {
          id: assertion.id,
          rawId: this.bufferToBase64url(assertion.rawId),
          type: assertion.type,
          response: {
            authenticatorData: this.bufferToBase64url(assertion.response.authenticatorData),
            clientDataJSON: this.bufferToBase64url(assertion.response.clientDataJSON),
            signature: this.bufferToBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle ? this.bufferToBase64url(assertion.response.userHandle) : undefined,
          },
        },
      }});
      this.user = result;
      this.connectSSE();
      this.navigate('dashboard');
    } catch (e) {
      if (errEl) { errEl.textContent = e.message || 'Passkey login failed'; errEl.style.display = 'block'; }
    }
  },

  async doRegister() {
    const errEl = document.getElementById('reg-error');
    try {
      errEl.style.display = 'none';
      this.user = await this.api('/auth/register', { method: 'POST', body: {
        username: document.getElementById('reg-user').value,
        email: document.getElementById('reg-email').value || undefined,
        password: document.getElementById('reg-pass').value,
      }});
      this.connectSSE();
      this.navigate(this.user.role === 'admin' ? 'domains' : 'dashboard');
      this.toast(`Welcome! You are ${this.user.role === 'admin' ? 'an admin — add your first domain below' : 'a viewer'}.`, 'success');
    } catch (e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  },

  renderForgotPassword() {
    document.getElementById('app').innerHTML = `
      <div class="auth-page"><div class="auth-card card">
        <h1>Reset Password</h1><p>Enter your email address to receive a reset link</p>
        <div class="form-group"><label>Email</label><input id="forgot-email" type="email" autocomplete="email"></div>
        <div id="forgot-error" class="form-error" style="display:none"></div>
        <div id="forgot-success" class="form-success" style="display:none"></div>
        <button class="btn-primary" id="forgot-btn" onclick="App.doForgotPassword()">Send Reset Link</button>
        <div class="auth-switch"><a href="#login">Back to sign in</a></div>
      </div></div>`;
    document.getElementById('forgot-email').focus();
    document.getElementById('forgot-email').addEventListener('keydown', (e) => { if (e.key === 'Enter') App.doForgotPassword(); });
  },

  async doForgotPassword() {
    const errEl = document.getElementById('forgot-error');
    const successEl = document.getElementById('forgot-success');
    const btn = document.getElementById('forgot-btn');
    try {
      errEl.style.display = 'none';
      successEl.style.display = 'none';
      btn.disabled = true;
      btn.textContent = 'Sending...';
      const result = await this.api('/auth/forgot-password', { method: 'POST', body: { email: document.getElementById('forgot-email').value } });
      successEl.textContent = result.message || 'If an account with that email exists, a reset link has been sent.';
      successEl.style.display = 'block';
      btn.textContent = 'Sent';
    } catch (e) {
      errEl.textContent = e.message;
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Send Reset Link';
    }
  },

  renderResetPassword(token) {
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return this.navigate('forgot-password');
    document.getElementById('app').innerHTML = `
      <div class="auth-page"><div class="auth-card card">
        <h1>Set New Password</h1><p>Enter your new password below</p>
        <div class="form-group"><label>New Password (min 8 chars)</label><input id="reset-pass" type="password" autocomplete="new-password"></div>
        <div class="form-group"><label>Confirm Password</label><input id="reset-pass-confirm" type="password" autocomplete="new-password"></div>
        <div id="reset-error" class="form-error" style="display:none"></div>
        <div id="reset-success" class="form-success" style="display:none"></div>
        <button class="btn-primary" id="reset-btn" onclick="App.doResetPassword('${token}')">Reset Password</button>
        <div class="auth-switch"><a href="#login">Back to sign in</a></div>
      </div></div>`;
    document.getElementById('reset-pass').focus();
    document.getElementById('reset-pass-confirm').addEventListener('keydown', (e) => { if (e.key === 'Enter') App.doResetPassword(token); });
  },

  async doResetPassword(token) {
    const errEl = document.getElementById('reset-error');
    const successEl = document.getElementById('reset-success');
    const btn = document.getElementById('reset-btn');
    const pass = document.getElementById('reset-pass').value;
    const confirm = document.getElementById('reset-pass-confirm').value;
    errEl.style.display = 'none';
    successEl.style.display = 'none';
    if (pass !== confirm) { errEl.textContent = 'Passwords do not match'; errEl.style.display = 'block'; return; }
    try {
      btn.disabled = true;
      btn.textContent = 'Resetting...';
      await this.api('/auth/reset-password', { method: 'POST', body: { token, newPassword: pass } });
      successEl.textContent = 'Password reset successfully. Redirecting to login...';
      successEl.style.display = 'block';
      setTimeout(() => this.navigate('login'), 2000);
    } catch (e) {
      errEl.textContent = e.message;
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Reset Password';
    }
  },

  async renderAcceptInvite(token) {
    if (!token || !/^[a-f0-9]{64}$/.test(token)) {
      document.getElementById('app').innerHTML = `
        <div class="auth-page"><div class="auth-card card">
          <h1>Invalid Invitation</h1><p>This invite link is invalid or malformed.</p>
          <div class="auth-switch"><a href="#login">Go to sign in</a></div>
        </div></div>`;
      return;
    }
    try {
      const invite = await fetch(`/api/auth/invite/${token}`).then(r => { if (!r.ok) throw new Error((r.json && r.json().then ? 'error' : 'Invalid invitation')); return r.json(); });
      document.getElementById('app').innerHTML = `
        <div class="auth-page"><div class="auth-card card">
          <h1>Accept Invitation</h1>
          <p>You've been invited as a <strong>${this.esc(invite.role)}</strong>.</p>
          <div class="form-group"><label>Email</label><input value="${this.esc(invite.email)}" disabled></div>
          <div class="form-group"><label>Username</label><input id="invite-user" autocomplete="username"></div>
          <div class="form-group"><label>Password (min 8 chars)</label><input id="invite-pass" type="password" autocomplete="new-password"></div>
          <div id="invite-error" class="form-error" style="display:none"></div>
          <button class="btn-primary" onclick="App.doAcceptInvite('${token}')">Create Account</button>
          <div class="auth-switch">Already have an account? <a href="#login">Sign in</a></div>
        </div></div>`;
      document.getElementById('invite-user').focus();
    } catch (e) {
      document.getElementById('app').innerHTML = `
        <div class="auth-page"><div class="auth-card card">
          <h1>Invitation Expired</h1><p>This invitation is no longer valid. Please ask an admin for a new invite.</p>
          <div class="auth-switch"><a href="#login">Go to sign in</a></div>
        </div></div>`;
    }
  },

  async doAcceptInvite(token) {
    const errEl = document.getElementById('invite-error');
    try {
      errEl.style.display = 'none';
      this.user = await this.api('/auth/accept-invite', { method: 'POST', body: {
        token,
        username: document.getElementById('invite-user').value,
        password: document.getElementById('invite-pass').value,
      }});
      this.connectSSE();
      this.navigate('dashboard');
      this.toast('Welcome! Your account has been created.', 'success');
    } catch (e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  },

  async logout() {
    await this.api('/auth/logout', { method: 'POST' }).catch(() => {});
    this.user = null;
    if (this.eventSource) this.eventSource.close();
    this.navigate('login');
  },

  // ─── Dashboard ───
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

      if (data.recent_changes.length > 0) {
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
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async scanAll() {
    try {
      const result = await this.api('/scan-all', { method: 'POST' });
      this.toast(`Started scanning ${result.started} domain(s)`, 'info');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async dismissRecord(id) {
    try {
      await this.api(`/records/${id}/dismiss`, { method: 'PUT', body: { dismissed: true } });
      this.toast('Record dismissed', 'success');
      this.renderDashboard();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── Domains List ───
  async renderDomains() {
    const isAdmin = this.user?.role === 'admin';
    this.renderLayout(`
      <div class="page-header"><h2>Domains</h2>
        ${isAdmin ? '<button class="btn-primary" onclick="App.showAddDomain()">+ Add Domain</button>' : ''}
      </div>
      <div class="search-bar">
        <input id="domain-search" placeholder="Search domains..." oninput="App.filterDomains()">
        <select id="domain-filter" onchange="App.filterDomains()">
          <option value="all">All</option><option value="dead">Has Dead Records</option><option value="healthy">Healthy</option><option value="disabled">Disabled</option>
        </select>
        ${isAdmin ? '<button class="btn-secondary" onclick="App.showImport()">Import CSV</button>' : ''}
      </div>
      <div id="domain-list"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div>
    `);
    try {
      this._domains = await this.api('/domains');
      this.filterDomains();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  filterDomains() {
    const search = (document.getElementById('domain-search')?.value || '').toLowerCase();
    const filter = document.getElementById('domain-filter')?.value || 'all';
    const el = document.getElementById('domain-list');
    if (!el || !this._domains) return;

    let filtered = this._domains;
    if (search) filtered = filtered.filter(d => d.domain.includes(search) || (d.display_name || '').toLowerCase().includes(search));
    if (filter === 'dead') filtered = filtered.filter(d => parseInt(d.dead_count) > 0);
    else if (filter === 'healthy') filtered = filtered.filter(d => parseInt(d.dead_count) === 0 && d.enabled);
    else if (filter === 'disabled') filtered = filtered.filter(d => !d.enabled);

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
      return `<div class="domain-card card" onclick="App.navigate('domains/${d.id}')">
        <div class="domain-dot ${dotClass}"></div>
        <div class="domain-info">
          <div class="domain-name">${this.esc(d.display_name || d.domain)} ${tagHtml}</div>
          <div class="domain-meta">${this.esc(d.domain)} &middot; ${d.record_count || 0} records &middot; ${deadCount > 0 ? `<span style="color:var(--status-dead)">${deadCount} dead</span>` : '0 dead'} &middot; Last scan: ${this.timeAgo(d.last_scan)}</div>
        </div>
        <div class="domain-actions" onclick="event.stopPropagation()">
          <button class="btn-sm btn-secondary" onclick="App.scanDomain(${d.id})" ${this.scanningDomains.has(d.id) ? 'disabled' : ''}>${this.scanningDomains.has(d.id) ? 'Scanning...' : 'Scan Now'}</button>
          ${isAdmin ? `<button class="btn-sm btn-icon" onclick="App.showEditDomain(${d.id})">&#9998;</button><button class="btn-sm btn-icon" onclick="App.deleteDomain(${d.id}, '${this.esc(d.domain)}')" style="color:var(--danger)">&#10005;</button>` : ''}
        </div>
      </div>`;
    }).join('');
  },

  async scanDomain(id) {
    try {
      this.scanningDomains.add(id);
      this.filterDomains();
      await this.api(`/domains/${id}/scan`, { method: 'POST' });
      this.toast('Scan started', 'info');
    } catch (e) {
      this.scanningDomains.delete(id);
      this.filterDomains();
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
          ${[60,180,360,720,1440].map(v => `<option value="${v}" ${domain.scan_interval_minutes === v ? 'selected' : ''}>${v < 60 ? v + ' min' : v/60 + ' hours'}</option>`).join('')}
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
      dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('dragover'); const f = e.dataTransfer.files[0]; if (f) { document.getElementById('csv-file').files = e.dataTransfer.files; App.handleCSV(document.getElementById('csv-file')); }});
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
      const changedCount = 0; // would need changes API

      let html = `
        <div class="page-header">
          <div>
            <h2>${this.esc(domain.display_name || domain.domain)}</h2>
            <div style="font-size:13px;color:var(--text-secondary);margin-top:4px">Last scan: ${this.timeAgo(domain.last_scan)} &middot; ${records.length} records found
              ${whois?.expiry_date ? ` &middot; Expires: <span style="color:${new Date(whois.expiry_date) < new Date(Date.now() + 30*86400000) ? 'var(--status-dead)' : 'var(--text-secondary)'}">${new Date(whois.expiry_date).toLocaleDateString()}</span>` : ''}</div>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn-primary" onclick="App.scanDomain(${id})" ${this.scanningDomains.has(parseInt(id)) ? 'disabled' : ''}>${this.scanningDomains.has(parseInt(id)) ? 'Scanning...' : 'Scan Now'}</button>
            <button class="btn-secondary" onclick="window.open('/api/domains/${id}/export/csv')">Export CSV</button>
            <button class="btn-secondary" onclick="window.open('/api/domains/${id}/export/report')">Report</button>
          </div>
        </div>
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

      // Trend chart placeholder
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

  _sortField: 'record_type',
  _sortDir: 1,
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

      return `<tr class="${rowClass}" onclick="App.showRecordDrawer(${r.id})">
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
    ctx.strokeStyle = 'var(--border)' in ctx ? '#e2e8f0' : '#e2e8f0';
    ctx.lineWidth = 1;

    const plotW = w - padding.left - padding.right;
    const plotH = h - padding.top - padding.bottom;
    const xStep = plotW / Math.max(data.length - 1, 1);

    // Grid
    ctx.strokeStyle = '#e2e8f030';
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

  // ─── Record Drawer ───
  async showRecordDrawer(recordId) {
    const record = this._currentRecords?.find(r => r.id === recordId);
    if (!record) return;

    const domain = this._currentDomain;
    const fullName = record.name === '@' ? domain.domain : `${record.name}.${domain.domain}`;

    const drawer = document.getElementById('drawer');
    const overlay = document.getElementById('modal-overlay');
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
    const allPorts = [443, 80, 22, 8443, 8080, 3389, 21];
    if (!['TXT', 'CAA', 'SOA'].includes(record.record_type)) {
      drawerHtml += `<div class="drawer-section"><h4>Ports Checked</h4><div class="port-list">`;
      for (const p of allPorts) {
        const open = ports.includes(p);
        const name = {443:'HTTPS',80:'HTTP',22:'SSH',8443:'8443',8080:'8080',3389:'RDP',21:'FTP'}[p] || p;
        drawerHtml += `<span class="port-badge ${open ? 'open' : 'closed'}">${name} (${p}) ${open ? '&#10004;' : '&#10008;'}</span>`;
      }
      drawerHtml += `</div></div>`;
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
          <button class="btn-secondary" onclick="App.dismissRecord(${record.id}); App.closeDrawer();">${record.dismissed ? 'Undismiss' : 'Dismiss Record'}</button>
        </div>
      </div>`;

    drawer.innerHTML = drawerHtml;
    drawer.classList.remove('hidden');
    requestAnimationFrame(() => drawer.classList.add('open'));
    overlay.classList.remove('hidden');
    overlay.onclick = () => this.closeDrawer();
  },

  closeDrawer() {
    const drawer = document.getElementById('drawer');
    const overlay = document.getElementById('modal-overlay');
    drawer.classList.remove('open');
    overlay.classList.add('hidden');
    setTimeout(() => drawer.classList.add('hidden'), 250);
  },

  // ─── Settings ───
  async renderSettings() {
    const isAdmin = this.user?.role === 'admin';
    this.renderLayout(`
      <div class="page-header"><h2>Settings</h2></div>
      <div class="settings-tabs">
        <button class="settings-tab active" onclick="App.showSettingsTab('profile', this)">Profile</button>
        <button class="settings-tab" onclick="App.showSettingsTab('notifications', this)">Notifications</button>
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'smtp\', this)">SMTP</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'webhooks\', this)">Webhooks</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'auth\', this)">Authentication</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'users\', this)">Users</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'tags\', this)">Tags</button>' : ''}
      </div>
      <div id="settings-content"></div>
    `);
    this.showSettingsTab('profile');
  },

  async showSettingsTab(tab, el) {
    document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
    if (el) el.classList.add('active');
    else document.querySelector(`.settings-tab`)?.classList.add('active');
    const content = document.getElementById('settings-content');
    if (!content) return;

    switch (tab) {
      case 'profile':
        const hasPassword = this.user.has_password !== false;
        content.innerHTML = `<div class="card" style="max-width:500px">
          <h3 style="margin-bottom:16px">Profile</h3>
          <div class="form-group"><label>Username</label><input value="${this.esc(this.user.username)}" disabled></div>
          <div class="form-group"><label>Email</label><input id="set-email" value="${this.esc(this.user.email || '')}"></div>
          <button class="btn-primary" onclick="App.updateProfile()">Save</button>
          <h3 style="margin:24px 0 16px">${hasPassword ? 'Change Password' : 'Set Password'}</h3>
          ${hasPassword ? '<div class="form-group"><label>Current Password</label><input id="set-curpass" type="password"></div>' : ''}
          <div class="form-group"><label>New Password</label><input id="set-newpass" type="password"></div>
          <button class="btn-primary" onclick="App.changePassword()">${hasPassword ? 'Update Password' : 'Set Password'}</button>
        </div>
        ${window.PublicKeyCredential ? `
        <div class="card" style="max-width:500px;margin-top:16px">
          <h3 style="margin-bottom:16px">Passkeys</h3>
          <p style="color:var(--text-muted);font-size:13px;margin-bottom:16px">Use passkeys for passwordless login, two-factor authentication, or as an alternative to your password.</p>
          ${this.user.passkey_count > 0 ? `
          <div class="form-group">
            <label>Passkey Mode</label>
            <select id="passkey-mode" onchange="App.setPasskeyMode(this.value)">
              <option value="either" ${this.user.passkey_mode === 'either' ? 'selected' : ''}>Either (password or passkey)</option>
              <option value="twofactor" ${this.user.passkey_mode === 'twofactor' ? 'selected' : ''}>Two-factor (password + passkey)</option>
              <option value="passwordless" ${this.user.passkey_mode === 'passwordless' ? 'selected' : ''}>Passwordless (passkey only)</option>
            </select>
          </div>` : ''}
          <div id="passkey-list" style="margin-bottom:16px"></div>
          <button class="btn-primary btn-sm" onclick="App.registerPasskey()">+ Register New Passkey</button>
        </div>` : ''}
        <div class="card" style="max-width:500px;margin-top:16px">
          <h3 style="margin-bottom:16px">Linked Accounts</h3>
          <div id="linked-accounts"></div>
        </div>`;
        if (window.PublicKeyCredential) this.loadPasskeys();
        this.loadLinkedAccounts();
        break;

      case 'notifications':
        try {
          const settings = await this.api('/notifications/settings');
          content.innerHTML = `<div class="card" style="max-width:500px">
            <h3 style="margin-bottom:16px">Push Notifications</h3>
            <label class="toggle"><input type="checkbox" id="ns-push" ${settings.push_enabled ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Enable push notifications</label>
            <div style="margin-top:8px"><button class="btn-sm btn-secondary" onclick="App.subscribePush()">Enable Browser Push</button> <button class="btn-sm btn-secondary" onclick="App.testPush()">Test Push</button></div>
            <hr style="margin:20px 0;border:none;border-top:1px solid var(--border)">
            <h3 style="margin-bottom:16px">Notification Types</h3>
            <div style="display:flex;flex-direction:column;gap:12px">
              <label class="toggle"><input type="checkbox" id="ns-dead" ${settings.notify_on_dead ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Notify when records go dead</label>
              <label class="toggle"><input type="checkbox" id="ns-recovery" ${settings.notify_on_recovery ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Notify when records recover</label>
              <label class="toggle"><input type="checkbox" id="ns-takeover" ${settings.notify_on_takeover_risk ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Notify on takeover risk</label>
              <label class="toggle"><input type="checkbox" id="ns-change" ${settings.notify_on_dns_change ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Notify on DNS changes</label>
              <label class="toggle"><input type="checkbox" id="ns-expiry" ${settings.notify_on_domain_expiry ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Notify on domain expiry</label>
            </div>
            <hr style="margin:20px 0;border:none;border-top:1px solid var(--border)">
            <h3 style="margin-bottom:16px">Email Notifications</h3>
            <label class="toggle"><input type="checkbox" id="ns-email" ${settings.email_enabled ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Enable email notifications</label>
            <div style="margin-top:8px"><button class="btn-sm btn-secondary" onclick="App.testEmail()">Test Email</button></div>
          </div>`;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading settings</p></div>`; }
        break;

      case 'smtp':
        try {
          const smtp = await this.api('/smtp');
          content.innerHTML = `<div class="card" style="max-width:500px">
            <h3 style="margin-bottom:16px">SMTP Configuration</h3>
            <div class="form-group"><label>Host</label><input id="smtp-host" value="${this.esc(smtp.smtp_host || '')}"></div>
            <div class="form-group"><label>Port</label><input id="smtp-port" type="number" value="${smtp.smtp_port || 587}"></div>
            <div class="form-group"><label>Username</label><input id="smtp-user" value="${this.esc(smtp.smtp_user || '')}"></div>
            <div class="form-group"><label>Password (optional)</label><input id="smtp-pass" type="password" placeholder="Leave blank if not required"></div>
            <label class="toggle" style="margin-bottom:16px"><input type="checkbox" id="smtp-secure" ${smtp.smtp_secure !== false ? 'checked' : ''}><div class="toggle-track"></div>Use TLS</label>
            <div style="display:flex;gap:8px"><button class="btn-primary" onclick="App.saveSMTP()">Save</button><button class="btn-secondary" onclick="App.testEmail()">Test</button></div>
          </div>`;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading SMTP config</p></div>`; }
        break;

      case 'webhooks':
        try {
          const webhooks = await this.api('/webhooks');
          let whtml = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3>Webhooks</h3><button class="btn-primary btn-sm" onclick="App.showAddWebhook()">+ Add Webhook</button></div>`;
          if (webhooks.length === 0) { whtml += '<div class="card"><p style="color:var(--text-muted)">No webhooks configured</p></div>'; }
          for (const wh of webhooks) {
            const events = (typeof wh.events === 'string' ? JSON.parse(wh.events) : wh.events) || [];
            whtml += `<div class="card" style="margin-bottom:8px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div><strong>${this.esc(wh.name)}</strong><div style="font-size:12px;color:var(--text-muted)">${this.esc(wh.url)}</div>
                  <div style="font-size:12px;margin-top:4px">${events.map(e => `<span class="status-badge info" style="margin:2px">${e}</span>`).join('')}</div>
                </div>
                <div style="display:flex;gap:4px">
                  <button class="btn-sm btn-secondary" onclick="App.testWebhook(${wh.id})">Test</button>
                  <button class="btn-sm btn-icon" style="color:var(--danger)" onclick="App.deleteWebhook(${wh.id})">&#10005;</button>
                </div>
              </div>
            </div>`;
          }
          content.innerHTML = whtml;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading webhooks</p></div>`; }
        break;

      case 'auth':
        try {
          const gs = await fetch('/api/auth/google/status').then(r => r.json());
          const googleConfigured = !!gs.clientId;
          content.innerHTML = `<div class="card" style="max-width:500px">
            <h3 style="margin-bottom:16px">Authentication Settings</h3>
            <h4 style="margin-bottom:8px">Google Sign-In</h4>
            ${gs.clientId ? `
              <label class="toggle"><input type="checkbox" id="google-auth-toggle" ${gs.enabled ? 'checked' : ''} onchange="App.toggleGoogleAuth(this.checked)"><div class="toggle-track"></div>Enable Google Sign-In</label>
              <p style="font-size:12px;color:var(--text-muted);margin-top:8px">Client ID: ${gs.clientId.substring(0, 20)}...</p>
            ` : '<p style="color:var(--text-muted);font-size:13px">Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables to enable.</p>'}
          </div>`;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading auth settings</p></div>`; }
        break;

      case 'users':
        try {
          const [users, invites] = await Promise.all([this.api('/users'), this.api('/users/invites')]);
          let uhtml = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3>Users</h3><button class="btn-primary btn-sm" onclick="App.showInviteUser()">+ Invite User</button></div>`;
          if (invites.length > 0) {
            uhtml += `<h4 style="margin-bottom:8px;color:var(--text-muted)">Pending Invitations</h4>`;
            for (const inv of invites) {
              uhtml += `<div class="card" style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
                <div><strong>${this.esc(inv.email)}</strong> <span class="status-badge info">${this.esc(inv.role)}</span>
                  <div style="font-size:12px;color:var(--text-muted)">Invited by ${this.esc(inv.invited_by_username || 'unknown')} &middot; Expires ${this.formatDate(inv.expires_at)}</div>
                </div>
                <button class="btn-sm btn-icon" style="color:var(--danger)" onclick="App.revokeInvite(${inv.id})">&#10005;</button>
              </div>`;
            }
          }
          uhtml += `<div class="card" style="overflow-x:auto;margin-top:16px">
            <table class="records-table"><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Created</th><th>Actions</th></tr></thead><tbody>`;
          for (const u of users) {
            uhtml += `<tr><td>${this.esc(u.username)}</td><td>${this.esc(u.email || '-')}</td>
              <td><select onchange="App.updateUserRole(${u.id}, this.value)" ${u.id === this.user.id ? 'disabled' : ''}>
                <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
                <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option>
              </select></td>
              <td>${this.formatDate(u.created_at)}</td>
              <td>${u.id !== this.user.id ? `<button class="btn-sm btn-icon" style="color:var(--danger)" onclick="App.deleteUser(${u.id}, '${this.esc(u.username)}')">&#10005;</button>` : ''}</td>
            </tr>`;
          }
          uhtml += `</tbody></table></div>`;
          content.innerHTML = uhtml;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading users</p></div>`; }
        break;

      case 'tags':
        try {
          const tags = await this.api('/tags');
          let thtml = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3>Tags</h3><button class="btn-primary btn-sm" onclick="App.showAddTag()">+ Add Tag</button></div>`;
          if (tags.length === 0) { thtml += '<div class="card"><p style="color:var(--text-muted)">No tags created</p></div>'; }
          for (const t of tags) {
            thtml += `<div class="card" style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
              <div><span class="tag" style="background:${this.esc(t.color)}">${this.esc(t.name)}</span></div>
              <div style="display:flex;gap:4px">
                <button class="btn-sm btn-icon" style="color:var(--danger)" onclick="App.deleteTag(${t.id})">&#10005;</button>
              </div>
            </div>`;
          }
          content.innerHTML = thtml;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading tags</p></div>`; }
        break;
    }
  },

  async updateProfile() {
    try {
      await this.api(`/users/${this.user.id}`, { method: 'PUT', body: { email: document.getElementById('set-email').value } });
      this.user = await this.api('/auth/me');
      this.toast('Profile updated', 'success');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async changePassword() {
    try {
      const body = { newPassword: document.getElementById('set-newpass').value };
      const curPassEl = document.getElementById('set-curpass');
      if (curPassEl) body.currentPassword = curPassEl.value;
      await this.api('/auth/password', { method: 'PUT', body });
      this.user = await this.api('/auth/me');
      this.toast('Password updated', 'success');
      if (curPassEl) curPassEl.value = '';
      document.getElementById('set-newpass').value = '';
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async loadPasskeys() {
    const container = document.getElementById('passkey-list');
    if (!container) return;
    try {
      const passkeys = await this.api('/auth/passkey/credentials');
      if (passkeys.length === 0) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:13px">No passkeys registered</p>';
        return;
      }
      container.innerHTML = passkeys.map(pk => `
        <div class="passkey-item">
          <div>
            <strong>${this.esc(pk.name)}</strong>
            <div style="font-size:12px;color:var(--text-muted)">${pk.device_type || 'Unknown device'} &middot; Added ${this.formatDate(pk.created_at)}${pk.last_used_at ? ' &middot; Last used ' + this.timeAgo(pk.last_used_at) : ''}</div>
          </div>
          <button class="btn-sm btn-icon" style="color:var(--danger)" onclick="App.deletePasskey(${pk.id})">&#10005;</button>
        </div>
      `).join('');
    } catch (e) { container.innerHTML = '<p style="color:var(--danger)">Failed to load passkeys</p>'; }
  },

  async registerPasskey() {
    try {
      const options = await this.api('/auth/passkey/register-options', { method: 'POST' });
      // Convert base64url fields to ArrayBuffers
      options.challenge = this.base64urlToBuffer(options.challenge);
      options.user.id = this.base64urlToBuffer(options.user.id);
      if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(c => ({ ...c, id: this.base64urlToBuffer(c.id) }));
      }
      const credential = await navigator.credentials.create({ publicKey: options });
      const name = prompt('Name this passkey (e.g., "MacBook Touch ID", "Phone"):', 'My Passkey');
      if (!name) return;
      await this.api('/auth/passkey/register-verify', { method: 'POST', body: {
        name,
        credential: {
          id: credential.id,
          rawId: this.bufferToBase64url(credential.rawId),
          type: credential.type,
          response: {
            attestationObject: this.bufferToBase64url(credential.response.attestationObject),
            clientDataJSON: this.bufferToBase64url(credential.response.clientDataJSON),
            transports: credential.response.getTransports ? credential.response.getTransports() : [],
          },
        },
      }});
      this.user = await this.api('/auth/me');
      this.toast('Passkey registered', 'success');
      this.showSettingsTab('profile');
    } catch (e) {
      if (e.name !== 'NotAllowedError') this.toast(e.message || 'Failed to register passkey', 'error');
    }
  },

  async deletePasskey(id) {
    if (!confirm('Delete this passkey?')) return;
    try {
      await this.api(`/auth/passkey/credentials/${id}`, { method: 'DELETE' });
      this.user = await this.api('/auth/me');
      this.toast('Passkey deleted', 'success');
      this.showSettingsTab('profile');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async setPasskeyMode(mode) {
    try {
      await this.api('/auth/passkey/mode', { method: 'PUT', body: { mode } });
      this.user.passkey_mode = mode;
      this.toast('Passkey mode updated', 'success');
    } catch (e) {
      this.toast(e.message, 'error');
      this.showSettingsTab('profile');
    }
  },

  async loadLinkedAccounts() {
    const container = document.getElementById('linked-accounts');
    if (!container) return;
    let googleEnabled = false;
    try {
      const gs = await fetch('/api/auth/google/status').then(r => r.json());
      googleEnabled = gs.enabled;
    } catch (e) {}

    let html = '';
    if (googleEnabled || this.user.google_linked) {
      html += `<div class="linked-account-item">
        <div style="display:flex;align-items:center;gap:8px">
          <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#34A853" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#FBBC05" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
          <span>Google</span>
        </div>
        ${this.user.google_linked
          ? '<button class="btn-sm btn-secondary" onclick="App.unlinkGoogle()">Unlink</button>'
          : '<button class="btn-sm btn-primary" onclick="window.location.href=\'/api/auth/google\'">Link Google</button>'}
      </div>`;
    }
    if (!html) html = '<p style="color:var(--text-muted);font-size:13px">No linked account options available</p>';
    container.innerHTML = html;
  },

  async unlinkGoogle() {
    if (!confirm('Unlink your Google account?')) return;
    try {
      await this.api('/auth/google/link', { method: 'DELETE' });
      this.user = await this.api('/auth/me');
      this.toast('Google account unlinked', 'success');
      this.showSettingsTab('profile');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async toggleGoogleAuth(enabled) {
    try {
      await this.api('/settings/google-auth', { method: 'PUT', body: { enabled } });
      this.toast(`Google Sign-In ${enabled ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async saveNotifSettings() {
    try {
      await this.api('/notifications/settings', { method: 'PUT', body: {
        push_enabled: document.getElementById('ns-push')?.checked,
        email_enabled: document.getElementById('ns-email')?.checked,
        notify_on_dead: document.getElementById('ns-dead')?.checked,
        notify_on_recovery: document.getElementById('ns-recovery')?.checked,
        notify_on_takeover_risk: document.getElementById('ns-takeover')?.checked,
        notify_on_dns_change: document.getElementById('ns-change')?.checked,
        notify_on_domain_expiry: document.getElementById('ns-expiry')?.checked,
      }});
      this.toast('Settings saved', 'success');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async subscribePush() {
    try {
      const { publicKey } = await this.api('/push/vapid-key');
      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: this.urlBase64ToUint8Array(publicKey),
      });
      await this.api('/push/subscribe', { method: 'POST', body: sub.toJSON() });
      this.toast('Push notifications enabled', 'success');
    } catch (e) { this.toast('Push setup failed: ' + e.message, 'error'); }
  },

  urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    return Uint8Array.from([...rawData].map(char => char.charCodeAt(0)));
  },

  async testPush() { try { await this.api('/notifications/test-push', { method: 'POST' }); this.toast('Test push sent', 'success'); } catch (e) { this.toast(e.message, 'error'); } },
  async testEmail() { try { await this.api('/notifications/test-email', { method: 'POST' }); this.toast('Test email sent', 'success'); } catch (e) { this.toast(e.message, 'error'); } },

  async saveSMTP() {
    try {
      await this.api('/smtp', { method: 'PUT', body: {
        smtp_host: document.getElementById('smtp-host').value,
        smtp_port: parseInt(document.getElementById('smtp-port').value),
        smtp_user: document.getElementById('smtp-user').value,
        smtp_pass: document.getElementById('smtp-pass').value,
        smtp_secure: document.getElementById('smtp-secure').checked,
      }});
      this.toast('SMTP config saved', 'success');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  async updateUserRole(id, role) {
    try { await this.api(`/users/${id}`, { method: 'PUT', body: { role } }); this.toast('Role updated', 'success'); } catch (e) { this.toast(e.message, 'error'); }
  },

  async deleteUser(id, name) {
    if (!confirm(`Delete user ${name}?`)) return;
    try { await this.api(`/users/${id}`, { method: 'DELETE' }); this.toast('User deleted', 'success'); this.showSettingsTab('users'); } catch (e) { this.toast(e.message, 'error'); }
  },

  showInviteUser() {
    this.showModal('Invite User', `
      <div class="form-group"><label>Email</label><input id="modal-invite-email" type="email" placeholder="user@example.com"></div>
      <div class="form-group"><label>Role</label><select id="modal-invite-role">
        <option value="viewer">Viewer</option>
        <option value="admin">Admin</option>
      </select></div>
    `, async () => {
      const result = await this.api('/users/invite', { method: 'POST', body: {
        email: document.getElementById('modal-invite-email').value,
        role: document.getElementById('modal-invite-role').value,
      }});
      if (result.warning) {
        this.toast(result.warning, 'warning');
      } else {
        this.toast('Invitation sent', 'success');
      }
      this.showSettingsTab('users');
    }, 'Send Invite');
  },

  async revokeInvite(id) {
    if (!confirm('Revoke this invitation?')) return;
    try { await this.api(`/users/invites/${id}`, { method: 'DELETE' }); this.toast('Invite revoked', 'success'); this.showSettingsTab('users'); } catch (e) { this.toast(e.message, 'error'); }
  },

  showAddTag() {
    this.showModal('Add Tag', `
      <div class="form-group"><label>Name</label><input id="modal-tag-name" placeholder="production"></div>
      <div class="form-group"><label>Color</label><input id="modal-tag-color" type="color" value="#3b82f6" style="height:40px"></div>
    `, async () => {
      await this.api('/tags', { method: 'POST', body: { name: document.getElementById('modal-tag-name').value, color: document.getElementById('modal-tag-color').value } });
      this.toast('Tag created', 'success');
      this.showSettingsTab('tags');
    });
  },

  async deleteTag(id) {
    if (!confirm('Delete this tag?')) return;
    try { await this.api(`/tags/${id}`, { method: 'DELETE' }); this.toast('Tag deleted', 'success'); this.showSettingsTab('tags'); } catch (e) { this.toast(e.message, 'error'); }
  },

  showAddWebhook() {
    const events = ['record.dead','record.recovered','record.takeover_risk','domain.expiry_warning','scan.completed','propagation.inconsistent','dns.changed'];
    this.showModal('Add Webhook', `
      <div class="form-group"><label>Name</label><input id="modal-wh-name" placeholder="Slack Alert"></div>
      <div class="form-group"><label>URL</label><input id="modal-wh-url" placeholder="https://hooks.slack.com/..."></div>
      <div class="form-group"><label>Events</label>
        ${events.map(e => `<label style="display:block;margin:4px 0"><input type="checkbox" class="wh-event" value="${e}" checked> ${e}</label>`).join('')}
      </div>
    `, async () => {
      const selectedEvents = [...document.querySelectorAll('.wh-event:checked')].map(e => e.value);
      await this.api('/webhooks', { method: 'POST', body: {
        name: document.getElementById('modal-wh-name').value,
        url: document.getElementById('modal-wh-url').value,
        events: selectedEvents,
      }});
      this.toast('Webhook created', 'success');
      this.showSettingsTab('webhooks');
    });
  },

  async testWebhook(id) { try { await this.api(`/webhooks/${id}/test`, { method: 'POST' }); this.toast('Test webhook sent', 'success'); } catch (e) { this.toast(e.message, 'error'); } },
  async deleteWebhook(id) { if (!confirm('Delete webhook?')) return; try { await this.api(`/webhooks/${id}`, { method: 'DELETE' }); this.toast('Deleted', 'success'); this.showSettingsTab('webhooks'); } catch (e) { this.toast(e.message, 'error'); } },

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
};

// Boot
App.init();
