// Relay Local Security Console Application
// Zero External Dependencies - 100% Local Loopback Execution
// High-Contrast, Authoritative Security UX (Deslopped, WCAG AAA)

(function () {
  'use strict';

  // State
  let sessionToken = null;
  let csrfToken = null;
  let currentView = 'overview';
  let activityCache = [];
  let autoRefreshInterval = 0; // 0 = off, 5000, 10000, 30000
  let autoRefreshTimer = null;
  let isRefreshing = false;

  // View navigation mapping
  const VIEWS = [
    { id: 'overview', name: 'Overview', shortcut: '1' },
    { id: 'activity', name: 'Activity', shortcut: '2' },
    { id: 'receipts', name: 'Receipts', shortcut: '3' },
    { id: 'ledger', name: 'Ledger', shortcut: '4' },
    { id: 'policies', name: 'Policies', shortcut: '5' },
    { id: 'secrets', name: 'Secrets', shortcut: '6' },
    { id: 'security', name: 'Security', shortcut: '7' },
    { id: 'egress', name: 'Egress', shortcut: '8' },
    { id: 'connectors', name: 'Connectors', shortcut: '9' },
    { id: 'doctor', name: 'Doctor', shortcut: '0' },
  ];

  // Helper: Vector SVG Icons (Zero Emoji Slop)
  function icon(name, size = 16) {
    const s = size;
    switch (name) {
      case 'shield':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
      case 'check':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
      case 'alert':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
      case 'x':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
      case 'info':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
      case 'copy':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
      case 'key':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-1.5 1.5L14 9l-1.5-1.5L11 9l-1.5-1.5L8 9M3 21l9-9a5 5 0 1 0-7.07-7.07L3 21z"/></svg>`;
      case 'lock':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
      case 'search':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`;
      case 'refresh':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`;
      case 'terminal':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`;
      case 'database':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`;
      case 'file':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
      case 'layers':
        return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>`;
      default:
        return '';
    }
  }

  // Helper: Escapes text for safe HTML rendering (XSS mitigation)
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  // Helper: Truncate hash with ellipsis
  function truncHash(str, len = 16) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '…' : str;
  }

  // Helper: Format ISO timestamp
  function formatTs(isoStr) {
    if (!isoStr) return '-';
    try {
      const d = new Date(isoStr);
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return isoStr;
    }
  }

  // Toast Notification System
  function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconName = 'info';
    if (type === 'success') iconName = 'check';
    if (type === 'warning') iconName = 'alert';
    if (type === 'error') iconName = 'x';

    toast.innerHTML = `
      <div style="display:flex;align-items:center;gap:0.5rem;">
        <span style="display:inline-flex;color:currentColor;">${icon(iconName, 16)}</span>
        <span>${escapeHtml(message)}</span>
      </div>
      <button style="background:none;border:none;color:var(--text-secondary);cursor:pointer;display:inline-flex;padding:0.2rem;" aria-label="Dismiss">${icon('x', 14)}</button>
    `;

    toast.querySelector('button').addEventListener('click', () => toast.remove());
    container.appendChild(toast);

    setTimeout(() => {
      if (toast.parentNode) {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(6px)';
        toast.style.transition = 'all 0.15s ease';
        setTimeout(() => toast.remove(), 150);
      }
    }, duration);
  }

  // Copy text to clipboard with toast notification
  async function copyToClipboard(text, label = 'Content') {
    if (!text) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      showToast(`${label} copied to clipboard`, 'success', 2000);
    } catch (err) {
      showToast(`Copy failed: ${err.message}`, 'error');
    }
  }

  // Modal Dialog System
  function openModal({ title, body, footer = null, onConfirm = null }) {
    const container = document.getElementById('modal-container');
    if (!container) return;

    container.style.display = 'flex';
    container.setAttribute('aria-hidden', 'false');
    container.className = 'modal-overlay';

    container.innerHTML = `
      <div class="modal-content" role="document">
        <div class="modal-header">
          <h2 class="modal-title">${title}</h2>
          <button id="modal-close-btn" class="btn btn-secondary btn-sm" aria-label="Close dialog" style="padding:0.3rem;">${icon('x', 14)}</button>
        </div>
        <div class="modal-body">${body}</div>
        <div class="modal-footer">
          ${footer ? footer : `
            <button id="modal-cancel-btn" class="btn btn-secondary">Close</button>
            ${onConfirm ? `<button id="modal-confirm-btn" class="btn btn-primary">Confirm</button>` : ''}
          `}
        </div>
      </div>
    `;

    document.getElementById('modal-close-btn').addEventListener('click', closeModal);
    const cancelBtn = document.getElementById('modal-cancel-btn');
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);

    container.addEventListener('click', (e) => {
      if (e.target === container) closeModal();
    });

    if (onConfirm) {
      document.getElementById('modal-confirm-btn').addEventListener('click', async () => {
        await onConfirm();
        closeModal();
      });
    }
  }

  function closeModal() {
    const container = document.getElementById('modal-container');
    if (container) {
      container.style.display = 'none';
      container.setAttribute('aria-hidden', 'true');
      container.innerHTML = '';
    }
  }

  // Keyboard Shortcuts Modal Guide
  function showShortcutsModal() {
    const body = `
      <div style="font-size:0.875rem;line-height:1.7;">
        <p style="color:var(--text-secondary);margin-bottom:1rem;">Keyboard shortcuts enable rapid operator navigation without mouse interaction:</p>
        <div style="display:grid;grid-template-columns:auto 1fr;gap:0.65rem 1.25rem;align-items:center;">
          <div><kbd>1</kbd> .. <kbd>9</kbd>, <kbd>0</kbd></div><div>Switch views (Overview, Activity, Receipts, Ledger, Policies, Secrets...)</div>
          <div><kbd>R</kbd></div><div>Refresh active view data</div>
          <div><kbd>/</kbd></div><div>Focus search / filter box in current view</div>
          <div><kbd>Esc</kbd></div><div>Close modal inspector or dialog</div>
          <div><kbd>?</kbd></div><div>Open this keyboard shortcut reference</div>
        </div>
      </div>
    `;
    openModal({ title: `${icon('terminal', 16)} Keyboard Navigation`, body });
  }

  // Cedar syntax highlighter
  function highlightCedar(code) {
    if (!code) return '';
    const lines = code.split('\n');
    return lines.map(line => {
      let l = escapeHtml(line);
      if (l.trim().startsWith('//')) {
        return `<span class="cedar-cmt">${l}</span>`;
      }
      l = l.replace(/"([^"]*)"/g, '<span class="cedar-str">"$1"</span>');
      l = l.replace(/\b(permit|forbid|when|unless)\b/g, '<span class="cedar-kw">$1</span>');
      l = l.replace(/\b(principal|action|resource|context)\b/g, '<span class="cedar-ent">$1</span>');
      l = l.replace(/\b(is|in|like|has)\b/g, '<span class="cedar-act">$1</span>');
      return l;
    }).join('\n');
  }

  // API Client with session and CSRF enforcement
  async function api(path, options = {}) {
    const headers = options.headers || {};
    if (sessionToken) {
      headers['X-Relay-Session'] = sessionToken;
    }
    if (csrfToken && (options.method === 'POST' || options.method === 'PUT' || options.method === 'DELETE')) {
      headers['X-Relay-CSRF'] = csrfToken;
    }
    options.headers = headers;

    const res = await fetch(path, options);
    if (res.status === 401) {
      sessionToken = null;
      csrfToken = null;
      renderAuthScreen('Session expired or unauthorized. Please re-enter your CLI session token.');
      throw new Error('Unauthorized');
    }
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(errText || `HTTP ${res.status}`);
    }
    return res.json();
  }

  // Authentication Bootstrap
  async function initAuth() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    if (token) {
      window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
      try {
        const data = await fetch('/api/v1/auth/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token.trim() }),
        }).then(r => {
          if (!r.ok) throw new Error('Token verification failed');
          return r.json();
        });

        sessionToken = data.session_token;
        csrfToken = data.csrf_token;
        sessionStorage.setItem('relay_sess', sessionToken);
        sessionStorage.setItem('relay_csrf', csrfToken);
        startApp();
        return;
      } catch (err) {
        renderAuthScreen('Invalid or expired authentication token. Please launch the console via `relay ui`.');
        return;
      }
    }

    const savedSess = sessionStorage.getItem('relay_sess');
    const savedCsrf = sessionStorage.getItem('relay_csrf');
    if (savedSess && savedCsrf) {
      sessionToken = savedSess;
      csrfToken = savedCsrf;
      try {
        await api('/api/v1/auth/check');
        startApp();
        return;
      } catch {
        sessionStorage.removeItem('relay_sess');
        sessionStorage.removeItem('relay_csrf');
      }
    }

    renderAuthScreen();
  }

  // Authentication Form Screen
  function renderAuthScreen(errorMsg = null) {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem;">
        <div class="card" style="max-width:440px;width:100%;border-color:var(--border-default);">
          <div style="display:flex;align-items:center;gap:0.65rem;margin-bottom:1.25rem;">
            <div style="color:var(--color-allow);display:flex;">${icon('shield', 24)}</div>
            <div>
              <div style="font-weight:700;font-size:1.15rem;letter-spacing:-0.02em;">Relay Security Console</div>
              <div style="font-size:0.78rem;color:var(--text-muted);font-family:var(--font-mono);">ZERO-TRUST GATEWAY & CEDAR PDP</div>
            </div>
          </div>

          <p style="font-size:0.875rem;color:var(--text-secondary);margin-bottom:1.25rem;line-height:1.6;">
            Local security console access requires single-use session authorization. Launch with <code class="mono" style="color:var(--text-primary)">relay ui</code> or enter your session token.
          </p>

          ${errorMsg ? `<div class="badge badge-deny" style="padding:0.65rem 0.85rem;border-radius:4px;margin-bottom:1rem;display:flex;align-items:center;gap:0.4rem;font-family:var(--font-sans);text-transform:none;">${icon('alert', 16)} ${escapeHtml(errorMsg)}</div>` : ''}

          <form id="auth-form" style="display:flex;flex-direction:column;gap:1rem;">
            <div>
              <label for="token-input" style="display:block;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-secondary);margin-bottom:0.4rem;">
                Bootstrap Session Token
              </label>
              <input id="token-input" type="password" required autocomplete="off" placeholder="Enter session token from CLI..." class="search-input" style="width:100%;" />
            </div>

            <button type="submit" class="btn btn-primary" style="width:100%;padding:0.6rem;">
              ${icon('key', 16)} Authenticate & Access Console
            </button>
          </form>

          <div style="margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--border-subtle);font-size:0.78rem;color:var(--text-muted);display:flex;justify-content:space-between;">
            <span>Loopback Only (127.0.0.1)</span>
            <span>Zero Telemetry</span>
          </div>
        </div>
      </div>
    `;

    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const val = document.getElementById('token-input').value.trim();
      if (!val) return;

      try {
        const data = await fetch('/api/v1/auth/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: val }),
        }).then(r => {
          if (!r.ok) throw new Error('Token verification failed');
          return r.json();
        });

        sessionToken = data.session_token;
        csrfToken = data.csrf_token;
        sessionStorage.setItem('relay_sess', sessionToken);
        sessionStorage.setItem('relay_csrf', csrfToken);
        startApp();
      } catch {
        renderAuthScreen('Invalid session token. Please run `relay ui` to generate a fresh token.');
      }
    });
  }

  // Main App Shell
  function startApp() {
    renderMainLayout();
    window.addEventListener('hashchange', handleRoute);
    window.addEventListener('keydown', handleGlobalKeydown);
    handleRoute();
  }

  function renderMainLayout() {
    const app = document.getElementById('app');
    app.innerHTML = `
      <header class="header">
        <a href="#overview" class="brand">
          <span style="color:var(--color-allow);display:flex;">${icon('shield', 22)}</span>
          <span>Relay</span>
          <span class="brand-badge">Console</span>
        </a>

        <nav class="nav" role="tablist">
          ${VIEWS.map(v => `
            <a href="#${v.id}" id="nav-${v.id}" class="nav-link ${v.id === currentView ? 'active' : ''}" role="tab" aria-selected="${v.id === currentView}">
              ${v.name}
              <kbd>${v.shortcut}</kbd>
            </a>
          `).join('')}
        </nav>

        <div class="header-meta">
          <div class="status-indicator protected">
            <span class="status-dot pulse-dot"></span>
            <span>Protected</span>
          </div>

          <div style="display:flex;align-items:center;gap:0.35rem;">
            <button id="refresh-btn" class="btn btn-secondary btn-sm" title="Refresh (Shortcut: R)" aria-label="Refresh view data">
              ${icon('refresh', 14)}
            </button>
            <button id="shortcuts-btn" class="btn btn-secondary btn-sm" title="Shortcuts (Shortcut: ?)" aria-label="Keyboard shortcuts">
              <kbd>?</kbd>
            </button>
          </div>
        </div>
      </header>

      <main class="container" id="view-container" role="main"></main>

      <footer class="footer">
        <div>Relay Security Gateway v0.1.0 • Fail-Closed Cedar Authorization</div>
        <div style="display:flex;gap:1.25rem;">
          <a href="#doctor">System Health</a>
          <a href="#security">Invariants</a>
          <a href="https://github.com/Sumeet-basfore/relay" target="_blank" rel="noopener">GitHub</a>
        </div>
      </footer>
    `;

    document.getElementById('refresh-btn').addEventListener('click', () => refreshCurrentView(true));
    document.getElementById('shortcuts-btn').addEventListener('click', showShortcutsModal);
  }

  // Routing Dispatch
  function handleRoute() {
    const hash = window.location.hash.replace('#', '').trim();
    if (hash.startsWith('activity/')) {
      const actionId = hash.replace('activity/', '');
      inspectAction(actionId);
      return;
    }

    const matched = VIEWS.find(v => v.id === hash);
    currentView = matched ? matched.id : 'overview';

    VIEWS.forEach(v => {
      const el = document.getElementById(`nav-${v.id}`);
      if (el) {
        if (v.id === currentView) {
          el.classList.add('active');
          el.setAttribute('aria-selected', 'true');
        } else {
          el.classList.remove('active');
          el.setAttribute('aria-selected', 'false');
        }
      }
    });

    renderCurrentView();
  }

  function handleGlobalKeydown(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
      if (e.key === 'Escape') {
        e.target.blur();
      }
      return;
    }

    if (e.key === 'Escape') {
      closeModal();
      return;
    }

    if (e.key === '?') {
      e.preventDefault();
      showShortcutsModal();
      return;
    }

    if (e.key === 'r' || e.key === 'R') {
      e.preventDefault();
      refreshCurrentView(true);
      return;
    }

    if (e.key === '/') {
      const searchBox = document.querySelector('.search-input');
      if (searchBox) {
        e.preventDefault();
        searchBox.focus();
        return;
      }
    }

    const matchedView = VIEWS.find(v => v.shortcut === e.key);
    if (matchedView) {
      e.preventDefault();
      window.location.hash = matchedView.id;
    }
  }

  async function refreshCurrentView(showFeedback = false) {
    if (isRefreshing) return;
    isRefreshing = true;
    try {
      await renderCurrentView();
      if (showFeedback) showToast('View data updated', 'success', 1500);
    } catch (err) {
      showToast(`Refresh error: ${err.message}`, 'error');
    } finally {
      isRefreshing = false;
    }
  }

  function renderCurrentView() {
    switch (currentView) {
      case 'overview': return renderOverview();
      case 'activity': return renderActivity();
      case 'receipts': return renderReceipts();
      case 'ledger': return renderLedger();
      case 'policies': return renderPolicies();
      case 'secrets': return renderSecrets();
      case 'security': return renderSecurity();
      case 'egress': return renderEgress();
      case 'connectors': return renderConnectors();
      case 'doctor': return renderDoctor();
      default: return renderOverview();
    }
  }

  // ===========================================================================
  // VIEW: Overview (Mission Control)
  // ===========================================================================
  async function renderOverview() {
    const container = document.getElementById('view-container');
    try {
      const [status, activityData] = await Promise.all([
        api('/api/v1/status'),
        api('/api/v1/activity?limit=6')
      ]);

      const items = activityData.items || [];
      activityCache = items;

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('shield', 22)} Gateway Posture Overview</h1>
            <p class="section-subtitle">Real-time Cedar PDP enforcement, DSSE receipt signing, and ledger integrity status.</p>
          </div>
          <div class="toolbar-group">
            <a href="#ledger" class="btn btn-secondary btn-sm">${icon('database', 14)} Verify Ledger</a>
            <a href="#doctor" class="btn btn-secondary btn-sm">${icon('terminal', 14)} Diagnostics</a>
          </div>
        </div>

        <div class="grid-4">
          <div class="card">
            <div class="card-header">
              <span class="card-title">Security State</span>
              <span class="badge badge-allow">${icon('check', 12)} ENFORCED</span>
            </div>
            <div class="card-value" style="color:var(--color-allow)">ACTIVE</div>
            <div class="card-subtext">Zero Ambient Credentials</div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Policy Engine</span>
              <span class="badge badge-brand">${icon('layers', 12)} CEDAR PDP</span>
            </div>
            <div class="card-value">Default Deny</div>
            <div class="card-subtext">${status.policy_count || 1} Strict Cedar Rules Loaded</div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Ledger Integrity</span>
              <span class="badge badge-allow">${icon('check', 12)} HASH CHAIN</span>
            </div>
            <div class="card-value">#${status.ledger_head_seq || 0}</div>
            <div class="card-subtext">${status.ledger_total_entries || 0} Immutable DSSE Entries</div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Egress Sandbox</span>
              <span class="badge badge-approval">${escapeHtml(status.sandbox_short_mode || 'ENFORCED')}</span>
            </div>
            <div class="card-value">${status.active_connectors || 4} Connectors</div>
            <div class="card-subtext">${escapeHtml(status.egress_sandbox_mode || 'Mediated Egress')}</div>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-header">
            <span class="card-title">System & Host Configuration</span>
            <span class="badge badge-neutral mono">${escapeHtml(status.target_os || 'linux')} / ${escapeHtml(status.target_arch || 'x86_64')}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:1rem;font-size:0.85rem;">
            <div>
              <span style="color:var(--text-secondary)">Relay Version:</span><br/>
              <span class="mono" style="font-weight:600;color:var(--text-primary);">${escapeHtml(status.relay_version)}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Signing Key ID (Ed25519):</span><br/>
              <span class="mono">${escapeHtml(status.signing_key_id || 'relay-ed25519-v1')}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Ledger Store:</span><br/>
              <span class="mono">${escapeHtml(status.ledger_path || '.relay/ledger.db')}</span>
            </div>
          </div>
        </div>

        <div class="view-header" style="margin-bottom:0.75rem;">
          <div>
            <h2 style="font-size:1.15rem;font-weight:700;">Recent Governed Actions</h2>
            <p class="section-subtitle">Real-time audit stream of tool execution decisions and signed receipts.</p>
          </div>
          <a href="#activity" class="btn btn-secondary btn-sm">View All Activity &rarr;</a>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Time</th>
                <th>Tool Name</th>
                <th>Resource / Target</th>
                <th>Decision</th>
                <th>Action Hash</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              ${items.length === 0 ? `
                <tr>
                  <td colspan="7" style="text-align:center;color:var(--text-muted);padding:2.5rem;">
                    No governed actions recorded yet.<br/>
                    <span style="font-size:0.78rem;">Run an MCP tool via <code class="mono">relay run -- &lt;server-command&gt;</code> to view live decisions.</span>
                  </td>
                </tr>
              ` : items.map(it => `
                <tr>
                  <td class="mono">#${it.sequence_number}</td>
                  <td>${formatTs(it.timestamp)}</td>
                  <td><span class="mono" style="font-weight:600;">${escapeHtml(it.tool_name)}</span></td>
                  <td><span class="mono" style="color:var(--text-secondary);">${escapeHtml(it.resource)}</span></td>
                  <td>
                    <span class="badge ${it.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny'}">
                      ${it.decision === 'ALLOW' ? icon('check', 11) : icon('x', 11)} ${escapeHtml(it.decision)}
                    </span>
                  </td>
                  <td>
                    <span class="hash-chip" onclick="window.relayCopy('${it.action_hash}', 'Action Hash')" title="Click to copy hash">
                      ${truncHash(it.action_hash, 12)} ${icon('copy', 11)}
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-secondary btn-sm" onclick="window.relayInspect('${it.action_id}')">
                      Inspect
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading overview: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Activity Stream (With Live Search & Decision Filter)
  // ===========================================================================
  async function renderActivity() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/activity?limit=100');
      const items = data.items || [];
      activityCache = items;

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('terminal', 22)} Governed Activity Stream</h1>
            <p class="section-subtitle">Complete chronological stream of intercepted tool calls, policy evaluations, and signed receipts.</p>
          </div>
          <div class="toolbar-group">
            <span id="activity-counter" class="badge badge-neutral mono">Total: ${items.length}</span>
          </div>
        </div>

        <div class="filter-bar">
          <input type="text" id="activity-search" class="search-input" placeholder="Search tool, resource, action hash... (Shortcut: /)" />
          <select id="activity-decision-filter" class="filter-select">
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW Only (Permitted)</option>
            <option value="DENY">DENY Only (Blocked)</option>
          </select>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Timestamp (UTC)</th>
                <th>Tool Name</th>
                <th>Resource Target</th>
                <th>Decision</th>
                <th>Action Hash</th>
                <th>Receipt ID</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="activity-tbody"></tbody>
          </table>
        </div>
      `;

      function filterAndRender() {
        const q = (document.getElementById('activity-search').value || '').toLowerCase();
        const dec = document.getElementById('activity-decision-filter').value;

        const filtered = items.filter(it => {
          if (dec !== 'ALL' && it.decision !== dec) return false;
          if (!q) return true;
          return (
            (it.tool_name || '').toLowerCase().includes(q) ||
            (it.resource || '').toLowerCase().includes(q) ||
            (it.action_hash || '').toLowerCase().includes(q) ||
            (it.receipt_id || '').toLowerCase().includes(q)
          );
        });

        document.getElementById('activity-counter').textContent = `Showing: ${filtered.length} of ${items.length}`;

        const tbody = document.getElementById('activity-tbody');
        if (filtered.length === 0) {
          tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:2rem;">No matching activity events found.</td></tr>`;
          return;
        }

        tbody.innerHTML = filtered.map(it => `
          <tr>
            <td class="mono">#${it.sequence_number}</td>
            <td>${formatTs(it.timestamp)}</td>
            <td><span class="mono" style="font-weight:600;">${escapeHtml(it.tool_name)}</span></td>
            <td><span class="mono" style="color:var(--text-secondary);">${escapeHtml(it.resource)}</span></td>
            <td>
              <span class="badge ${it.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny'}">
                ${it.decision === 'ALLOW' ? icon('check', 11) : icon('x', 11)} ${escapeHtml(it.decision)}
              </span>
            </td>
            <td>
              <span class="hash-chip" onclick="window.relayCopy('${it.action_hash}', 'Action Hash')" title="Copy Action Hash">
                ${truncHash(it.action_hash, 12)} ${icon('copy', 11)}
              </span>
            </td>
            <td>
              <span class="hash-chip" onclick="window.relayCopy('${it.receipt_id}', 'Receipt ID')" title="Copy Receipt ID">
                ${truncHash(it.receipt_id, 10)} ${icon('copy', 11)}
              </span>
            </td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="window.relayInspect('${it.action_id}')">
                Inspect
              </button>
            </td>
          </tr>
        `).join('');
      }

      document.getElementById('activity-search').addEventListener('input', filterAndRender);
      document.getElementById('activity-decision-filter').addEventListener('change', filterAndRender);
      filterAndRender();

    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading activity: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Receipts (RFC 9598 DSSE In-Toto Attestations)
  // ===========================================================================
  async function renderReceipts() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/receipts?limit=50');
      const receipts = data.receipts || [];

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('file', 22)} Cryptographic Action Receipts</h1>
            <p class="section-subtitle">Signed in-toto attestation statements bound by Ed25519 digital signatures (RFC 9598 DSSE).</p>
          </div>
          <div class="toolbar-group">
            <span class="badge badge-neutral mono">Total: ${receipts.length}</span>
          </div>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Receipt ID</th>
                <th>Action ID</th>
                <th>Created At</th>
                <th>Signer Key ID</th>
                <th>Action Hash</th>
                <th>Verify Receipt</th>
              </tr>
            </thead>
            <tbody>
              ${receipts.length === 0 ? `
                <tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2.5rem;">No receipts generated yet.</td></tr>
              ` : receipts.map(r => `
                <tr>
                  <td>
                    <span class="hash-chip" onclick="window.relayCopy('${r.receipt_id}', 'Receipt ID')">
                      ${truncHash(r.receipt_id, 14)} ${icon('copy', 11)}
                    </span>
                  </td>
                  <td>
                    <span class="mono" style="color:var(--text-secondary);">${truncHash(r.action_id, 14)}</span>
                  </td>
                  <td>${formatTs(r.created_at)}</td>
                  <td><span class="mono">${escapeHtml(r.signing_key_id)}</span></td>
                  <td>
                    <span class="hash-chip" onclick="window.relayCopy('${r.action_hash}', 'Action Hash')">
                      ${truncHash(r.action_hash, 12)} ${icon('copy', 11)}
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-secondary btn-sm" id="verify-btn-${escapeHtml(r.receipt_id)}" onclick="window.relayVerifyReceipt('${r.receipt_id}')">
                      Verify Signature
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading receipts: ${escapeHtml(err.message)}</div>`;
    }
  }

  // Helper: Verify single receipt
  window.relayVerifyReceipt = async function (receiptId) {
    const btn = document.getElementById(`verify-btn-${receiptId}`);
    if (btn) btn.textContent = 'Verifying...';

    try {
      const res = await api(`/api/v1/receipts/${receiptId}/verify`);
      if (res.is_valid) {
        showToast(`Receipt ${truncHash(receiptId, 10)} signature VALID (Ed25519 verified)`, 'success');
        if (btn) {
          btn.className = 'btn btn-success btn-sm';
          btn.innerHTML = `${icon('check', 11)} Valid`;
        }
      } else {
        showToast(`Receipt verification FAILED: ${res.reason || 'Invalid signature'}`, 'error');
        if (btn) {
          btn.className = 'btn btn-danger btn-sm';
          btn.innerHTML = `${icon('x', 11)} Invalid`;
        }
      }
    } catch (err) {
      showToast(`Verification error: ${err.message}`, 'error');
      if (btn) btn.textContent = 'Verify Signature';
    }
  };

  // ===========================================================================
  // VIEW: Ledger (Cryptographic SHA-256 Audit Chain)
  // ===========================================================================
  async function renderLedger() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/ledger?limit=50');
      const entries = data.entries || [];

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('database', 22)} Immutable Audit Ledger</h1>
            <p class="section-subtitle">Append-only SQLite ledger with continuous SHA-256 hash chaining and strict permissions (0600).</p>
          </div>
          <div class="toolbar-group">
            <button id="verify-ledger-btn" class="btn btn-primary btn-sm">
              ${icon('check', 13)} Verify Full Hash Chain
            </button>
          </div>
        </div>

        <div id="ledger-verify-result"></div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Seq #</th>
                <th>Receipt ID</th>
                <th>Entry Hash</th>
                <th>Previous Hash (Binding)</th>
                <th>Timestamp (UTC)</th>
              </tr>
            </thead>
            <tbody>
              ${entries.length === 0 ? `
                <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:2.5rem;">Ledger is empty.</td></tr>
              ` : entries.map(e => `
                <tr>
                  <td class="mono" style="font-weight:700;">#${e.sequence_number}</td>
                  <td>
                    <span class="hash-chip" onclick="window.relayCopy('${e.receipt_id}', 'Receipt ID')">
                      ${truncHash(e.receipt_id, 14)} ${icon('copy', 11)}
                    </span>
                  </td>
                  <td>
                    <span class="mono" style="color:var(--color-allow);">${truncHash(e.entry_hash, 16)}</span>
                  </td>
                  <td>
                    <span class="mono" style="color:var(--text-muted);">${truncHash(e.previous_hash, 16)}</span>
                  </td>
                  <td>${formatTs(e.timestamp)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;

      document.getElementById('verify-ledger-btn').addEventListener('click', async () => {
        const btn = document.getElementById('verify-ledger-btn');
        btn.disabled = true;
        btn.innerHTML = `${icon('refresh', 13)} Verifying Hash Chain...`;

        try {
          const report = await api('/api/v1/ledger/verify');
          const resBox = document.getElementById('ledger-verify-result');

          if (report.is_valid) {
            resBox.innerHTML = `
              <div class="card" style="border-color:var(--color-allow);background:var(--color-allow-bg);margin-bottom:1.25rem;">
                <div style="display:flex;align-items:center;gap:0.65rem;">
                  <span style="color:var(--color-allow);display:flex;">${icon('check', 20)}</span>
                  <div>
                    <strong style="color:var(--color-allow);font-size:0.95rem;">Audit Ledger Hash Chain Cryptographically Verified</strong><br/>
                    <span style="color:var(--text-secondary);font-size:0.825rem;">Verified ${report.head_sequence || 0} consecutive blocks in ${report.duration_ms || 0}ms without tamper detection.</span>
                  </div>
                </div>
              </div>
            `;
          } else {
            resBox.innerHTML = `
              <div class="card" style="border-color:var(--color-deny);background:var(--color-deny-bg);margin-bottom:1.25rem;">
                <div style="display:flex;align-items:center;gap:0.65rem;">
                  <span style="color:var(--color-deny);display:flex;">${icon('x', 20)}</span>
                  <div>
                    <strong style="color:var(--color-deny);font-size:0.95rem;">Tamper Alert: Ledger Verification Failure</strong><br/>
                    <span style="color:var(--text-secondary);font-size:0.825rem;">${escapeHtml(report.error_message || 'Hash chain integrity violated!')}</span>
                  </div>
                </div>
              </div>
            `;
          }
        } catch (err) {
          showToast(`Ledger verify failed: ${err.message}`, 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = `${icon('check', 13)} Verify Full Hash Chain`;
        }
      });

    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading ledger: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Policies (Cedar Engine & Interactive Validator)
  // ===========================================================================
  async function renderPolicies() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/policies');

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('layers', 22)} Cedar Authorization Policies</h1>
            <p class="section-subtitle">Authoritative Cedar default-deny security policies enforcing strict schema conformity.</p>
          </div>
          <div class="toolbar-group">
            <span class="badge badge-allow mono">Default Deny Active</span>
            <span class="hash-chip" onclick="window.relayCopy('${data.policy_digest}', 'Policy Digest')" title="Copy Policy Digest">
              Digest: ${truncHash(data.policy_digest, 12)} ${icon('copy', 11)}
            </span>
          </div>
        </div>

        <div class="grid-3" style="margin-bottom:1.25rem;">
          <div class="card">
            <div class="card-header">
              <span class="card-title">Tier 1: Read-Only</span>
              <span class="badge badge-allow">Permit</span>
            </div>
            <div style="font-size:0.85rem;color:var(--text-secondary);line-height:1.5;">
              Queries, listings, and file content reads. Executed immediately without operator friction.
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Tier 2: Mutation</span>
              <span class="badge badge-approval">Approval Gated</span>
            </div>
            <div style="font-size:0.85rem;color:var(--text-secondary);line-height:1.5;">
              State writes, branch creations, database updates. Requires interactive step-up approval.
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Tier 3: Destructive & Sensitive</span>
              <span class="badge badge-deny">Forbid / Mandatory</span>
            </div>
            <div style="font-size:0.85rem;color:var(--text-secondary);line-height:1.5;">
              Shell executions, drops, file removals, sensitive credential targets (<code class="mono">~/.ssh</code>, <code class="mono">.env</code>).
            </div>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-header">
            <span class="card-title">Active Cedar Policy Rules</span>
            <button class="btn btn-secondary btn-sm" onclick="window.relayCopy(\`${escapeHtml(data.policy_text).replace(/`/g, '\\`')}\`, 'Policy Text')">
              ${icon('copy', 12)} Copy Policy Source
            </button>
          </div>
          <pre><code>${highlightCedar(data.policy_text)}</code></pre>
        </div>

        <div class="card">
          <div class="card-header">
            <span class="card-title">Interactive Cedar Policy Test Bench</span>
            <span class="badge badge-brand mono">Validator</span>
          </div>
          <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:0.75rem;">
            Test custom Cedar security policy syntax against Relay's compiled schema before saving to disk:
          </p>
          <textarea id="policy-test-input" class="search-input" style="width:100%;height:130px;font-family:var(--font-mono);font-size:0.85rem;margin-bottom:0.75rem;padding:0.75rem;" placeholder="permit(principal, action == Relay::Action::&quot;read_resource&quot;, resource);"></textarea>
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div id="policy-test-feedback"></div>
            <button id="validate-policy-btn" class="btn btn-primary btn-sm">
              ${icon('check', 13)} Validate Policy
            </button>
          </div>
        </div>
      `;

      document.getElementById('validate-policy-btn').addEventListener('click', async () => {
        const text = document.getElementById('policy-test-input').value.trim();
        const fb = document.getElementById('policy-test-feedback');
        if (!text) {
          fb.innerHTML = `<span style="color:var(--color-approval);font-size:0.8rem;">Please enter policy text to validate.</span>`;
          return;
        }

        try {
          const res = await api('/api/v1/policies/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ policy_text: text }),
          });

          if (res.is_valid) {
            fb.innerHTML = `
              <span class="badge badge-allow mono">
                ${icon('check', 12)} VALID: ${res.policy_count || 1} rule(s) passed schema verification
              </span>
            `;
          } else {
            fb.innerHTML = `
              <span class="badge badge-deny mono">
                ${icon('x', 12)} ${escapeHtml(res.error || 'Syntax or schema error')}
              </span>
            `;
          }
        } catch (err) {
          fb.innerHTML = `<span style="color:var(--color-deny);font-size:0.8rem;">Validation error: ${escapeHtml(err.message)}</span>`;
        }
      });

    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading policies: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Secrets Vault (Keyring & Authenticated Storage)
  // ===========================================================================
  async function renderSecrets() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/secrets');
      const secrets = data.secrets || [];

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('key', 22)} Keyring Secret Vault</h1>
            <p class="section-subtitle">Zero-ambient credential vault backed by native OS Keyring with zeroized memory management.</p>
          </div>
          <div class="toolbar-group">
            <span class="badge badge-neutral mono">Configured Secrets: ${secrets.length}</span>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.25rem;">
          <div class="card-header">
            <span class="card-title">Vault Configuration & Storage</span>
            <span class="badge badge-allow">${icon('lock', 12)} ZERO LEAKAGE</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;font-size:0.85rem;">
            <div>
              <span style="color:var(--text-secondary)">Keyring Service Namespace:</span><br/>
              <span class="mono" style="font-weight:600;color:var(--text-primary);">io.relay.gateway</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Vault Storage Directory:</span><br/>
              <span class="mono">${escapeHtml(data.vault_dir || '~/.relay')}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Memory Isolation:</span><br/>
              <span class="mono" style="color:var(--color-allow);">Zeroize-on-drop / Locked RAM</span>
            </div>
          </div>
        </div>

        <div class="filter-bar">
          <input type="text" id="secret-search" class="search-input" placeholder="Search secret key alias or fingerprint..." />
          <span style="font-size:0.8rem;color:var(--text-muted);">
            Manage via CLI: <code class="mono" style="color:var(--text-primary)">relay secret set &lt;key&gt; &lt;val&gt;</code>
          </span>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Key Alias</th>
                <th>Storage Provider</th>
                <th>Payload Size</th>
                <th>SHA-256 Fingerprint</th>
                <th>Masked Value</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody id="secrets-tbody"></tbody>
          </table>
        </div>
      `;

      function renderSecretList() {
        const q = (document.getElementById('secret-search').value || '').toLowerCase();
        const filtered = secrets.filter(s => {
          if (!q) return true;
          return (s.alias || '').toLowerCase().includes(q) || (s.fingerprint || '').toLowerCase().includes(q);
        });

        const tbody = document.getElementById('secrets-tbody');
        if (filtered.length === 0) {
          tbody.innerHTML = `
            <tr>
              <td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem;">
                No secrets configured in vault.<br/>
                <span style="font-size:0.78rem;">Use <code class="mono">relay secret set &lt;key&gt; &lt;value&gt;</code> to securely vault API tokens.</span>
              </td>
            </tr>
          `;
          return;
        }

        tbody.innerHTML = filtered.map(s => `
          <tr>
            <td><span class="mono" style="font-weight:600;">${escapeHtml(s.alias)}</span></td>
            <td><span class="badge badge-brand">${escapeHtml(s.provider)}</span></td>
            <td><span class="mono">${s.length} bytes</span></td>
            <td>
              <span class="hash-chip" onclick="window.relayCopy('${s.fingerprint}', 'Fingerprint')" title="Copy Fingerprint">
                ${escapeHtml(s.fingerprint)} ${icon('copy', 11)}
              </span>
            </td>
            <td><span class="mono" style="color:var(--text-muted);">[MASKED - ${s.length} bytes]</span></td>
            <td>${formatTs(s.updated_at)}</td>
          </tr>
        `).join('');
      }

      document.getElementById('secret-search').addEventListener('input', renderSecretList);
      renderSecretList();

    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading secrets: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Security Invariants & Pipeline Architecture
  // ===========================================================================
  async function renderSecurity() {
    const container = document.getElementById('view-container');
    try {
      const sec = await api('/api/v1/security');

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('shield', 22)} Security Architecture & Invariants</h1>
            <p class="section-subtitle">Formal trust boundaries, kernel sandbox mechanisms, and security invariants.</p>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-title" style="margin-bottom:0.75rem;">Relay Zero-Trust Pipeline Flow</div>
          <pre><code>[ UNTRUSTED AGENT ] ── stdio (JSON-RPC) ──► [ TRUST BOUNDARY 1 ]
                                                  │
                                                  ▼
                                       ┌─────────────────────┐
                                       │    RELAY GATEWAY    │
                                       │ 1. Canonicalize     │
                                       │ 2. Authorize (Cedar)│
                                       │ 3. Human Gate (/dev)│
                                       │ 4. JIT Credential   │
                                       │ 5. DSSE Receipt     │
                                       │ 6. Append Ledger    │
                                       └──────────┬──────────┘
                                                  │
                ┌─────────────────────────────────┼─────────────────────────────────┐
                ▼                                 ▼                                 ▼
   [ FILESYSTEM CONNECTOR ]           [ POSTGRES CONNECTOR ]             [ GITHUB CONNECTOR ]
     Path Jail Enforcement              AST Read-Only Enforce             Loopback Egress Proxy</code></pre>
        </div>

        <div class="grid-2">
          <div class="card">
            <div class="card-title">Host Sandbox Enforcement</div>
            <div style="margin-top:0.75rem;font-size:0.875rem;line-height:1.6;">
              <p><strong>Host Platform:</strong> <span class="mono">${escapeHtml(sec.target_os)}</span></p>
              <p><strong>Sandbox Mode:</strong> <span class="badge ${sec.is_linux_netns ? 'badge-allow' : 'badge-approval'}">${escapeHtml(sec.egress_mode)}</span></p>
              <div style="margin-top:0.75rem;padding:0.75rem;background:var(--bg-surface);border-radius:4px;border:1px solid var(--border-subtle);">
                ${sec.is_linux_netns ?
                  '<strong>Linux Kernel Namespaces:</strong> Unprivileged network namespaces isolate child subprocess network stacks completely from host network and LAN interfaces.' :
                  '<strong>Cooperative Proxy Mode:</strong> On macOS/Windows, raw socket mediation relies on cooperative loopback proxying (HTTP_PROXY/HTTPS_PROXY).'}
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Core Security Invariants</div>
            <ul style="margin-top:0.75rem;font-size:0.85rem;padding-left:1.25rem;color:var(--text-secondary);line-height:1.7;">
              <li><strong style="color:var(--text-primary)">SI-001:</strong> Agent environment contains zero ambient target credentials.</li>
              <li><strong style="color:var(--text-primary)">SI-004:</strong> Every governed operation requires deterministic Cedar authorization.</li>
              <li><strong style="color:var(--text-primary)">SI-008:</strong> Destructive operations require out-of-band operator confirmation.</li>
              <li><strong style="color:var(--text-primary)">SI-011:</strong> Every action produces a cryptographically signed DSSE Action Receipt.</li>
              <li><strong style="color:var(--text-primary)">SI-014:</strong> Audit ledger is immutable, append-only, and hash-chained.</li>
            </ul>
          </div>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading security: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Egress & Anti-SSRF Protection
  // ===========================================================================
  async function renderEgress() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/egress');

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('shield', 22)} External Egress & Anti-SSRF Defense</h1>
            <p class="section-subtitle">Mediation boundary preventing cloud metadata access, private LAN scanning, and DNS rebinding.</p>
          </div>
        </div>

        <div class="grid-3">
          <div class="card">
            <div class="card-title">Loopback Proxy</div>
            <div class="card-value" style="color:var(--color-allow);">${escapeHtml(data.proxy_status || 'RUNNING')}</div>
            <div class="card-subtext">${escapeHtml(data.bind_addr || '127.0.0.1:Loopback')}</div>
          </div>
          <div class="card">
            <div class="card-title">Active Proxy Leases</div>
            <div class="card-value">${data.active_sessions || 0}</div>
            <div class="card-subtext">Short-Lived JIT Leases</div>
          </div>
          <div class="card">
            <div class="card-title">Anti-SSRF Protection</div>
            <div class="card-value" style="color:var(--color-allow);">ACTIVE</div>
            <div class="card-subtext">169.254.169.254 & RFC 1918 Blocked</div>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-title">Egress Protection Mechanisms</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;margin-top:0.75rem;font-size:0.85rem;">
            <div style="padding:0.75rem;background:var(--bg-surface);border-radius:4px;border:1px solid var(--border-subtle);">
              <strong style="color:var(--color-deny);">Cloud Metadata Shield</strong><br/>
              Requests to 169.254.169.254 and link-local IPv6 ranges are dropped immediately before connection.
            </div>
            <div style="padding:0.75rem;background:var(--bg-surface);border-radius:4px;border:1px solid var(--border-subtle);">
              <strong style="color:var(--color-approval);">DNS Rebinding Mitigation</strong><br/>
              Hostnames resolving to private RFC 1918 addresses are rejected during address resolution.
            </div>
            <div style="padding:0.75rem;background:var(--bg-surface);border-radius:4px;border:1px solid var(--border-subtle);">
              <strong style="color:var(--color-allow);">Header Sanitization</strong><br/>
              Subprocesses cannot forge Relay authorization headers or egress credentials in transit.
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading egress: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Tool Connectors
  // ===========================================================================
  async function renderConnectors() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/connectors');
      const connectors = data.connectors || [];

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('layers', 22)} Governed Connectors</h1>
            <p class="section-subtitle">Native in-process connectors and subprocess execution adapters governed by Relay.</p>
          </div>
        </div>

        <div class="grid-2">
          ${connectors.map(c => `
            <div class="card">
              <div class="card-header">
                <span class="card-title">${escapeHtml(c.name)}</span>
                <span class="badge ${c.is_available ? 'badge-allow' : 'badge-neutral'}">
                  ${c.is_available ? icon('check', 11) + ' AVAILABLE' : 'OFFLINE'}
                </span>
              </div>
              <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:0.75rem;">${escapeHtml(c.description)}</p>
              <div style="font-size:0.8rem;line-height:1.7;color:var(--text-muted);">
                <div>Security Mode: <span class="mono" style="color:var(--text-primary);">${escapeHtml(c.security_mode)}</span></div>
                <div>Isolation: <span class="mono" style="color:var(--text-primary);">${escapeHtml(c.isolation)}</span></div>
                <div>Credential Injection: <span class="mono" style="color:var(--text-primary);">${escapeHtml(c.credential_mode)}</span></div>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading connectors: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // VIEW: Doctor (Diagnostics)
  // ===========================================================================
  async function renderDoctor() {
    const container = document.getElementById('view-container');
    try {
      const doc = await api('/api/v1/doctor');

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">${icon('terminal', 22)} System Health Diagnostics</h1>
            <p class="section-subtitle">Canonical system health diagnostics matching <code class="mono">relay doctor</code> output.</p>
          </div>
          <div class="toolbar-group">
            <span class="badge ${doc.is_healthy ? 'badge-allow' : 'badge-deny'} mono">
              ${doc.is_healthy ? icon('check', 12) + ' HEALTHY' : icon('x', 12) + ' ATTENTION REQUIRED'}
            </span>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-header">
            <span class="card-title">Foundation Report</span>
            <span class="badge badge-neutral mono">${escapeHtml(doc.relay_version)}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;font-size:0.85rem;">
            <div>
              <span style="color:var(--text-secondary)">Platform / Target:</span><br/>
              <span class="mono">${escapeHtml(doc.target_os)} (${escapeHtml(doc.target_arch)})</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Working Directory:</span><br/>
              <span class="mono">${escapeHtml(doc.working_directory)}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Ledger File Status:</span><br/>
              <span class="mono">${escapeHtml(doc.ledger_path)} [${doc.ledger_exists ? 'EXISTS' : 'NOT INITIALIZED'}]</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Controlling Terminal (/dev/tty):</span><br/>
              <span class="badge ${doc.tty_available ? 'badge-allow' : 'badge-approval'}">
                ${doc.tty_available ? 'INTERACTIVE /DEV/TTY' : 'HEADLESS / FAIL-CLOSED'}
              </span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Sandbox Egress Mode:</span><br/>
              <span class="badge badge-brand">${escapeHtml(doc.egress_sandbox_mode)}</span>
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-deny" style="padding:1rem;display:block;">Error loading diagnostics: ${escapeHtml(err.message)}</div>`;
    }
  }

  // ===========================================================================
  // INSPECT ACTION MODAL (Tabbed In-Toto DSSE Viewer)
  // ===========================================================================
  async function inspectAction(actionId) {
    try {
      const data = await api(`/api/v1/activity/${actionId}`);
      const act = data.action;

      const body = `
        <div class="tabs">
          <button class="tab-btn active" onclick="window.relaySwitchTab('tab-summary')">Summary</button>
          <button class="tab-btn" onclick="window.relaySwitchTab('tab-proposal')">Canonical Proposal</button>
          <button class="tab-btn" onclick="window.relaySwitchTab('tab-receipt')">In-Toto Receipt</button>
        </div>

        <div id="tab-summary" class="tab-pane">
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:0.75rem;margin-bottom:1rem;font-size:0.85rem;">
            <div><span style="color:var(--text-secondary);">Tool Name:</span><br/><strong class="mono">${escapeHtml(act.tool_name)}</strong></div>
            <div><span style="color:var(--text-secondary);">Decision:</span><br/><span class="badge ${act.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny'}">${escapeHtml(act.decision)}</span></div>
            <div><span style="color:var(--text-secondary);">Action Hash:</span><br/><span class="mono">${truncHash(act.action_hash, 16)}</span></div>
            <div><span style="color:var(--text-secondary);">Sequence #:</span><br/><span class="mono">#${act.sequence_number}</span></div>
          </div>
          <div>
            <span style="color:var(--text-secondary);font-size:0.8rem;display:block;margin-bottom:0.35rem;">Resource Target:</span>
            <pre><code>${escapeHtml(act.resource || '-')}</code></pre>
          </div>
        </div>

        <div id="tab-proposal" class="tab-pane" style="display:none;">
          <pre><code>${escapeHtml(JSON.stringify(act.proposal || {}, null, 2))}</code></pre>
        </div>

        <div id="tab-receipt" class="tab-pane" style="display:none;">
          <pre><code>${escapeHtml(JSON.stringify(act.receipt || {}, null, 2))}</code></pre>
        </div>
      `;

      openModal({
        title: `${icon('shield', 18)} Action Inspection: ${escapeHtml(act.tool_name)}`,
        body,
        footer: `
          <button class="btn btn-secondary btn-sm" onclick="window.relayCopy(\`${escapeHtml(JSON.stringify(act, null, 2)).replace(/`/g, '\\`')}\`, 'Action Detail')">
            ${icon('copy', 12)} Copy Full JSON
          </button>
          <button class="btn btn-secondary" onclick="window.relayCloseModal()">Close</button>
        `
      });

    } catch (err) {
      showToast(`Failed to inspect action: ${err.message}`, 'error');
    }
  }

  // Global window bridge for inline event handlers
  window.relayCopy = copyToClipboard;
  window.relayInspect = inspectAction;
  window.relayCloseModal = closeModal;
  window.relaySwitchTab = function (tabId) {
    document.querySelectorAll('.tab-pane').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    const target = document.getElementById(tabId);
    if (target) target.style.display = 'block';
    if (event && event.target) event.target.classList.add('active');
  };

  // Launch on page load
  window.addEventListener('DOMContentLoaded', initAuth);
})();
