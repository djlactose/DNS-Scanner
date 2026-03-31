Object.assign(App, {
  async renderSettings() {
    const isAdmin = this.user?.role === 'admin';
    this.renderLayout(`
      <div class="page-header"><h2>Settings</h2></div>
      <div class="settings-tabs">
        <button class="settings-tab active" onclick="App.showSettingsTab('profile', this)">Profile</button>
        <button class="settings-tab" onclick="App.showSettingsTab('notifications', this)">Notifications</button>
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'system\', this)">System</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'smtp\', this)">SMTP</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'webhooks\', this)">Webhooks</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'auth\', this)">Authentication</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'users\', this)">Users</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'tags\', this)">Tags</button>' : ''}
        ${isAdmin ? '<button class="settings-tab" onclick="App.showSettingsTab(\'audit\', this)">Audit Log</button>' : ''}
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
      case 'system':
        try {
          const sysSettings = await this.api('/settings/system');
          const categories = { general: 'General', auth: 'Authentication & OAuth', scanner: 'Scanner Performance', integrations: 'DNS Provider Integrations' };
          let shtml = '<h3 style="margin-bottom:16px">System Settings</h3>';
          shtml += '<p style="color:var(--text-muted);font-size:13px;margin-bottom:16px">These settings can also be seeded from Docker environment variables on first run. Once saved here, the database values take precedence.</p>';
          for (const [catKey, catLabel] of Object.entries(categories)) {
            const items = sysSettings[catKey] || [];
            if (items.length === 0) continue;
            shtml += `<div class="card" style="max-width:600px;margin-bottom:16px"><h4 style="margin-bottom:12px">${catLabel}</h4>`;
            for (const s of items) {
              if (s.type === 'boolean') {
                shtml += `<label class="toggle" style="margin-bottom:12px">
                  <input type="checkbox" class="sys-setting" data-key="${s.key}" ${s.value === 'true' ? 'checked' : ''}>
                  <div class="toggle-track"></div>
                  <div><span>${this.esc(s.label)}</span>${s.description ? `<div style="font-size:12px;color:var(--text-muted)">${this.esc(s.description)}</div>` : ''}</div>
                </label>`;
              } else if (s.type === 'number') {
                shtml += `<div class="form-group" style="margin-bottom:12px">
                  <label>${this.esc(s.label)}</label>
                  ${s.description ? `<div style="font-size:12px;color:var(--text-muted);margin-bottom:4px">${this.esc(s.description)}</div>` : ''}
                  <input type="number" class="sys-setting" data-key="${s.key}" value="${this.esc(s.value)}">
                </div>`;
              } else {
                shtml += `<div class="form-group" style="margin-bottom:12px">
                  <label>${this.esc(s.label)}${s.sensitive ? ' (encrypted)' : ''}</label>
                  ${s.description ? `<div style="font-size:12px;color:var(--text-muted);margin-bottom:4px">${this.esc(s.description)}</div>` : ''}
                  <input type="${s.sensitive ? 'password' : 'text'}" class="sys-setting" data-key="${s.key}"
                    value="${s.sensitive ? '' : this.esc(s.value || '')}"
                    placeholder="${s.sensitive ? (s.hasValue ? 'Leave blank to keep current' : 'Not set') : ''}">
                </div>`;
              }
            }
            shtml += '</div>';
          }
          shtml += '<button class="btn-primary" onclick="App.saveSystemSettings()">Save Settings</button>';
          content.innerHTML = shtml;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading system settings: ${this.esc(e.message)}</p></div>`; }
        break;

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
        </div>
        <div class="card" style="max-width:500px;margin-top:16px">
          <h3 style="margin-bottom:16px">API Keys</h3>
          <p style="color:var(--text-muted);font-size:13px;margin-bottom:16px">Use API keys for automation. Include as: Authorization: Bearer &lt;key&gt;</p>
          <div id="api-keys-list"></div>
          <button class="btn-primary btn-sm" onclick="App.generateApiKey()">+ Generate New Key</button>
        </div>`;
        if (window.PublicKeyCredential) this.loadPasskeys();
        this.loadLinkedAccounts();
        this.loadApiKeys();
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
              <label class="toggle"><input type="checkbox" id="ns-cert-expiry" ${settings.notify_on_cert_expiry ? 'checked' : ''} onchange="App.saveNotifSettings()"><div class="toggle-track"></div>Notify on certificate expiry</label>
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
            <div class="form-group"><label>From Address</label><input id="smtp-from" value="${this.esc(smtp.smtp_from || '')}" placeholder="noreply@example.com"></div>
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
          content.innerHTML = `<div class="card" style="max-width:500px">
            <h3 style="margin-bottom:16px">Authentication Settings</h3>
            <h4 style="margin-bottom:8px">Google Sign-In</h4>
            ${gs.clientId ? `
              <label class="toggle"><input type="checkbox" id="google-auth-toggle" ${gs.enabled ? 'checked' : ''} onchange="App.toggleGoogleAuth(this.checked)"><div class="toggle-track"></div>Enable Google Sign-In</label>
              <p style="font-size:12px;color:var(--text-muted);margin-top:8px">Client ID: ${gs.clientId.substring(0, 20)}...</p>
            ` : '<p style="color:var(--text-muted);font-size:13px">Google OAuth not configured. Set the Google Client ID and Secret in <a href="#settings" onclick="App.showSettingsTab(\'system\', document.querySelector(\'.settings-tab\'))">System Settings</a>.</p>'}
          </div>`;
        } catch (e) { content.innerHTML = `<div class="card"><p>Error loading auth settings</p></div>`; }
        break;

      case 'users':
        try {
          const [users, invites] = await Promise.all([this.api('/users'), this.api('/users/invites')]);
          let uhtml = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h3>Users</h3>
            <div style="display:flex;gap:8px">
              <button class="btn-secondary btn-sm" onclick="App.exportUsers()">Export CSV</button>
              <button class="btn-secondary btn-sm" onclick="App.importUsers()">Import CSV</button>
              <button class="btn-primary btn-sm" onclick="App.showInviteUser()">+ Invite User</button>
            </div>
          </div>`;
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
            <table class="records-table"><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Access</th><th>Created</th><th>Actions</th></tr></thead><tbody>`;
          for (const u of users) {
            const allowedTags = u.allowed_tags ? (typeof u.allowed_tags === 'string' ? JSON.parse(u.allowed_tags) : u.allowed_tags) : [];
            const accessLabel = allowedTags.length > 0 ? allowedTags.map(t => this.esc(t)).join(', ') : '<span style="color:var(--text-muted)">All</span>';
            uhtml += `<tr><td>${this.esc(u.username)}</td><td>${this.esc(u.email || '-')}</td>
              <td><select onchange="App.updateUserRole(${u.id}, this.value)" ${u.id === this.user.id ? 'disabled' : ''}>
                <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
                <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option>
              </select></td>
              <td><button class="btn-sm btn-secondary" onclick="App.editUserAccess(${u.id}, '${this.esc(u.username)}', ${this.esc(JSON.stringify(allowedTags))})">${accessLabel}</button></td>
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

      case 'audit':
        this.loadAuditLog(1);
        break;
    }
  },

  // ─── Profile Actions ───
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

  // ─── Passkeys ───
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

  // ─── Linked Accounts ───
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

  // ─── API Keys ───
  async loadApiKeys() {
    const container = document.getElementById('api-keys-list');
    if (!container) return;
    try {
      const keys = await this.api('/auth/api-keys');
      if (keys.length === 0) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;margin-bottom:12px">No API keys generated</p>';
        return;
      }
      container.innerHTML = keys.map(k => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border-subtle)">
          <div>
            <strong>${this.esc(k.name)}</strong>
            <div style="font-size:12px;color:var(--text-muted)">Created ${this.formatDate(k.created_at)}${k.last_used_at ? ' &middot; Last used ' + this.timeAgo(k.last_used_at) : ' &middot; Never used'}</div>
          </div>
          <button class="btn-sm btn-icon" style="color:var(--danger)" onclick="App.deleteApiKey(${k.id})">&#10005;</button>
        </div>
      `).join('') + '<div style="margin-bottom:12px"></div>';
    } catch (e) { container.innerHTML = '<p style="color:var(--danger);font-size:13px;margin-bottom:12px">Failed to load API keys</p>'; }
  },

  async generateApiKey() {
    this.showModal('Generate API Key', `
      <div class="form-group"><label>Key Name</label><input id="modal-key-name" placeholder="e.g., CI/CD Pipeline"></div>
      <div id="generated-key-display" style="display:none;margin-top:12px">
        <label style="font-weight:600;margin-bottom:4px;display:block">Your API Key (copy now - it won't be shown again):</label>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="generated-key-value" readonly style="font-family:monospace;font-size:12px;flex:1">
          <button class="btn-sm btn-secondary" onclick="navigator.clipboard.writeText(document.getElementById('generated-key-value').value); App.toast('Copied!', 'success')">Copy</button>
        </div>
      </div>
    `, async () => {
      const name = document.getElementById('modal-key-name').value;
      if (!name) throw new Error('Name is required');
      const result = await this.api('/auth/api-keys', { method: 'POST', body: { name } });
      if (result.key) {
        const display = document.getElementById('generated-key-display');
        const input = document.getElementById('generated-key-value');
        if (display && input) {
          input.value = result.key;
          display.style.display = 'block';
          document.getElementById('modal-key-name').disabled = true;
        }
        // Don't close the modal - let the user copy the key first
        throw new Error('__keep_open__');
      }
      this.loadApiKeys();
    }, 'Generate');
  },

  async deleteApiKey(id) {
    if (!confirm('Delete this API key? Any integrations using it will stop working.')) return;
    try {
      await this.api(`/auth/api-keys/${id}`, { method: 'DELETE' });
      this.toast('API key deleted', 'success');
      this.loadApiKeys();
    } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── Notifications ───
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
        notify_on_cert_expiry: document.getElementById('ns-cert-expiry')?.checked,
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

  async testPush() {
    try { await this.api('/notifications/test-push', { method: 'POST' }); this.toast('Test push sent', 'success'); } catch (e) { this.toast(e.message, 'error'); }
  },

  async testEmail() {
    try { await this.api('/notifications/test-email', { method: 'POST' }); this.toast('Test email sent', 'success'); } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── SMTP ───
  async saveSMTP() {
    try {
      await this.api('/smtp', { method: 'PUT', body: {
        smtp_host: document.getElementById('smtp-host').value,
        smtp_port: parseInt(document.getElementById('smtp-port').value),
        smtp_user: document.getElementById('smtp-user').value,
        smtp_pass: document.getElementById('smtp-pass').value,
        smtp_from: document.getElementById('smtp-from').value,
        smtp_secure: document.getElementById('smtp-secure').checked,
      }});
      this.toast('SMTP config saved', 'success');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── Auth Settings ───
  async toggleGoogleAuth(enabled) {
    try {
      await this.api('/settings/google-auth', { method: 'PUT', body: { enabled } });
      this.toast(`Google Sign-In ${enabled ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── System Settings ───
  async saveSystemSettings() {
    const inputs = document.querySelectorAll('.sys-setting');
    const body = {};
    for (const input of inputs) {
      const key = input.dataset.key;
      if (input.type === 'checkbox') {
        body[key] = String(input.checked);
      } else if (input.type === 'password' && !input.value) {
        continue; // skip empty password fields (keep current)
      } else {
        body[key] = input.value;
      }
    }
    try {
      await this.api('/settings/system', { method: 'PUT', body });
      this.toast('System settings saved', 'success');
    } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── User Management ───
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

  async updateUserRole(id, role) {
    try { await this.api(`/users/${id}`, { method: 'PUT', body: { role } }); this.toast('Role updated', 'success'); } catch (e) { this.toast(e.message, 'error'); }
  },

  async deleteUser(id, name) {
    if (!confirm(`Delete user ${name}?`)) return;
    try { await this.api(`/users/${id}`, { method: 'DELETE' }); this.toast('User deleted', 'success'); this.showSettingsTab('users'); } catch (e) { this.toast(e.message, 'error'); }
  },

  async editUserAccess(id, username, currentTags) {
    try {
      const tags = await this.api('/tags');
      const parsedCurrent = typeof currentTags === 'string' ? JSON.parse(currentTags) : (currentTags || []);
      this.showModal(`Edit Access: ${username}`, `
        <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px">Select which tags this user can access. Leave all unchecked for full access.</p>
        <div class="form-group">
          ${tags.length > 0 ? tags.map(t => `<label style="display:block;margin:4px 0"><input type="checkbox" class="access-tag" value="${this.esc(t.name)}" ${parsedCurrent.includes(t.name) ? 'checked' : ''}> <span class="tag" style="background:${this.esc(t.color)}">${this.esc(t.name)}</span></label>`).join('') : '<p style="color:var(--text-muted)">No tags available. Create tags first.</p>'}
        </div>
      `, async () => {
        const selectedTags = [...document.querySelectorAll('.access-tag:checked')].map(e => e.value);
        await this.api(`/users/${id}`, { method: 'PUT', body: { allowed_tags: selectedTags } });
        this.toast('User access updated', 'success');
        this.showSettingsTab('users');
      });
    } catch (e) { this.toast(e.message, 'error'); }
  },

  exportUsers() {
    window.open('/api/users/export', '_blank');
  },

  importUsers() {
    this.showModal('Import Users from CSV', `
      <p style="margin-bottom:12px;font-size:13px;color:var(--text-secondary)">CSV format: email, role (admin/viewer)</p>
      <div class="drop-zone" id="user-drop-zone" onclick="document.getElementById('user-csv-file').click()">
        <p>Click or drag a CSV file here</p>
        <input type="file" id="user-csv-file" accept=".csv" style="display:none">
      </div>
    `, async () => {
      const file = document.getElementById('user-csv-file').files[0];
      if (!file) throw new Error('Select a CSV file');
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/api/users/import', { method: 'POST', body: formData });
      if (!res.ok) throw new Error((await res.json()).error);
      const result = await res.json();
      this.toast(`Imported ${result.imported || 0} user(s)`, 'success');
      this.showSettingsTab('users');
    }, 'Import');
  },

  // ─── Tags ───
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

  // ─── Webhooks ───
  showAddWebhook() {
    const events = ['record.dead', 'record.recovered', 'record.takeover_risk', 'domain.expiry_warning', 'cert.expiry_warning', 'scan.completed', 'propagation.inconsistent', 'dns.changed'];
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

  async testWebhook(id) {
    try { await this.api(`/webhooks/${id}/test`, { method: 'POST' }); this.toast('Test webhook sent', 'success'); } catch (e) { this.toast(e.message, 'error'); }
  },

  async deleteWebhook(id) {
    if (!confirm('Delete webhook?')) return;
    try { await this.api(`/webhooks/${id}`, { method: 'DELETE' }); this.toast('Deleted', 'success'); this.showSettingsTab('webhooks'); } catch (e) { this.toast(e.message, 'error'); }
  },

  // ─── Audit Log ───
  async loadAuditLog(page = 1) {
    const content = document.getElementById('settings-content');
    if (!content) return;
    content.innerHTML = '<div class="skeleton skeleton-card"></div>';
    try {
      const limit = 25;
      const offset = (page - 1) * limit;
      const data = await this.api(`/audit-log?limit=${limit}&offset=${offset}`);
      const logs = data.logs || data;
      const total = data.total || logs.length;
      const totalPages = Math.ceil(total / limit);

      let html = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <h3>Audit Log</h3>
        <span style="color:var(--text-muted);font-size:13px">${total} entries</span>
      </div>`;

      if (logs.length === 0) {
        html += '<div class="card"><p style="color:var(--text-muted)">No audit log entries</p></div>';
      } else {
        html += `<div class="card" style="overflow-x:auto">
          <table class="records-table">
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead>
            <tbody>`;
        for (const entry of logs) {
          html += `<tr>
            <td style="white-space:nowrap">${this.formatDate(entry.created_at || entry.timestamp)}</td>
            <td>${this.esc(entry.username || entry.user || '-')}</td>
            <td><span class="status-badge info">${this.esc(entry.action || '-')}</span></td>
            <td>${this.esc(entry.target || entry.resource || '-')}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${this.esc(typeof entry.details === 'object' ? JSON.stringify(entry.details) : (entry.details || '-'))}</td>
            <td>${this.esc(entry.ip || entry.ip_address || '-')}</td>
          </tr>`;
        }
        html += `</tbody></table></div>`;

        // Pagination
        if (totalPages > 1) {
          html += `<div style="display:flex;justify-content:center;gap:8px;margin-top:16px">`;
          if (page > 1) {
            html += `<button class="btn-sm btn-secondary" onclick="App.loadAuditLog(${page - 1})">Previous</button>`;
          }
          html += `<span style="padding:6px 12px;font-size:13px;color:var(--text-muted)">Page ${page} of ${totalPages}</span>`;
          if (page < totalPages) {
            html += `<button class="btn-sm btn-secondary" onclick="App.loadAuditLog(${page + 1})">Next</button>`;
          }
          html += `</div>`;
        }
      }

      content.innerHTML = html;
    } catch (e) { content.innerHTML = `<div class="card"><p>Error loading audit log: ${this.esc(e.message)}</p></div>`; }
  },
});
