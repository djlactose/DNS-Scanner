Object.assign(App, {
  renderLogin() {
    document.getElementById('app').innerHTML = `
      <div class="auth-page"><div class="auth-card card">
        <h1>DNS Scanner</h1><p>Sign in to your account</p>
        <div class="form-group"><label>Username</label><input id="login-user" autocomplete="username"></div>
        <div class="form-group"><label>Password</label><input id="login-pass" type="password" autocomplete="current-password"></div>
        <div id="login-error" class="form-error" style="display:none"></div>
        <button class="btn-primary" onclick="App.doLogin()">Sign In</button>
        ${window.PublicKeyCredential ? `
          <div class="auth-divider">or</div>
          <button class="btn-secondary btn-passkey" onclick="App.doPasskeyLogin()">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><circle cx="12" cy="16.5" r="1.5"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            Sign in with Passkey
          </button>` : ''}
        <div id="google-login-area"></div>
        <div class="auth-switch">
          <a href="#forgot-password">Forgot password?</a>
        </div>
        <div class="auth-switch">Don't have an account? <a href="#register">Register</a></div>
      </div></div>`;
    document.getElementById('login-pass')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') App.doLogin(); });
    // Check Google auth status
    fetch('/api/auth/google/status').then(r => r.json()).then(gs => {
      if (gs.enabled && gs.clientId) {
        document.getElementById('google-login-area').innerHTML = `
          <div class="auth-divider">or</div>
          <a href="/api/auth/google" class="btn-secondary btn-google" style="text-decoration:none;text-align:center">
            <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
            Sign in with Google
          </a>`;
      }
    }).catch(() => {});
  },

  async doLogin() {
    const errEl = document.getElementById('login-error');
    try {
      errEl.style.display = 'none';
      const result = await this.api('/auth/login', { method: 'POST', body: {
        username: document.getElementById('login-user').value,
        password: document.getElementById('login-pass').value,
      }});
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
      const invite = await fetch(`/api/auth/invite/${token}`).then(r => { if (!r.ok) throw new Error('Invalid invitation'); return r.json(); });
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
});
