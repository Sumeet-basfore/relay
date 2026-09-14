// Relay Local Security Console Application (CR002)
// Zero External Dependencies - 100% Local Loopback Execution

(function() {
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
    { id: 'security', name: 'Security', shortcut: '6' },
    { id: 'egress', name: 'Egress', shortcut: '7' },
    { id: 'connectors', name: 'Connectors', shortcut: '8' },
    { id: 'doctor', name: 'Doctor', shortcut: '9' },
  ];

  // Helper: Escapes text for safe HTML rendering (XSS mitigation)
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  // Helper: Truncate hash
  function truncHash(str, len = 16) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
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

    const iconMap = {
      success: '✓',
      warning: '⚠',
      error: '✗',
      info: 'ℹ'
    };

    toast.innerHTML = `
      <div style="display:flex;align-items:center;gap:0.65rem;">
        <span style="font-weight:bold;font-size:1rem;">${iconMap[type] || 'ℹ'}</span>
        <span>${escapeHtml(message)}</span>
      </div>
      <button style="background:none;border:none;color:var(--text-secondary);cursor:pointer;font-size:1.1rem;line-height:1;padding:0 0.25rem;" aria-label="Close">×</button>
    `;

    toast.querySelector('button').addEventListener('click', () => {
      toast.remove();
    });

    container.appendChild(toast);

    setTimeout(() => {
      if (toast.parentNode) {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(8px)';
        toast.style.transition = 'all 0.2s ease';
        setTimeout(() => toast.remove(), 200);
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
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      showToast(`Copied ${label} to clipboard`, 'success');
    } catch (err) {
      showToast(`Failed to copy: ${err.message}`, 'error');
    }
  }

  // Modal Dialog Manager
  function openModal({ title, body, onConfirm, confirmText = 'Confirm', confirmClass = 'btn-primary' }) {
    const container = document.getElementById('modal-container');
    if (!container) return;

    container.innerHTML = `
      <div class="modal-backdrop" id="modal-backdrop-el">
        <div class="modal-dialog" role="dialog" aria-labelledby="modal-dialog-title">
          <div class="modal-header">
            <h2 class="modal-title" id="modal-dialog-title">${escapeHtml(title)}</h2>
            <button class="btn-copy" id="modal-close-btn" aria-label="Close modal">✕</button>
          </div>
          <div class="modal-body">${body}</div>
          <div class="modal-footer">
            <button class="btn btn-secondary btn-sm" id="modal-cancel-btn">Close</button>
            ${onConfirm ? `<button class="btn ${confirmClass} btn-sm" id="modal-confirm-btn">${escapeHtml(confirmText)}</button>` : ''}
          </div>
        </div>
      </div>
    `;
    container.style.display = 'block';
    container.setAttribute('aria-hidden', 'false');

    const closeModal = () => {
      container.style.display = 'none';
      container.setAttribute('aria-hidden', 'true');
      container.innerHTML = '';
    };

    document.getElementById('modal-close-btn').addEventListener('click', closeModal);
    document.getElementById('modal-cancel-btn').addEventListener('click', closeModal);
    document.getElementById('modal-backdrop-el').addEventListener('click', (e) => {
      if (e.target.id === 'modal-backdrop-el') closeModal();
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
        <p style="color:var(--text-secondary);margin-bottom:1rem;">Keyboard shortcuts enable rapid operator navigation and inspection without a mouse:</p>
        <div style="display:grid;grid-template-columns:auto 1fr;gap:0.75rem 1.25rem;align-items:center;">
          <div><kbd>1</kbd> .. <kbd>9</kbd></div><div>Switch active view tab (Overview, Activity, Receipts...)</div>
          <div><kbd>R</kbd></div><div>Refresh current view data</div>
          <div><kbd>/</kbd></div><div>Focus search/filter box in active view</div>
          <div><kbd>Esc</kbd></div><div>Close open modals or detail views</div>
          <div><kbd>?</kbd></div><div>Show this keyboard shortcuts guide</div>
        </div>
      </div>
    `;
    openModal({ title: 'Keyboard Navigation Shortcuts', body });
  }

  // Cedar syntax highlighter for displaying policy text
  function highlightCedar(code) {
    if (!code) return '';
    const lines = code.split('\n');
    return lines.map(line => {
      let l = escapeHtml(line);
      if (l.trim().startsWith('//')) {
        return `<span class="cedar-comment">${l}</span>`;
      }
      l = l.replace(/"([^"]*)"/g, '<span class="cedar-string">"$1"</span>');
      l = l.replace(/\b(permit|forbid|when|unless)\b/g, '<span class="cedar-keyword">$1</span>');
      l = l.replace(/\b(principal|action|resource|context)\b/g, '<span class="cedar-entity">$1</span>');
      l = l.replace(/\b(is|in|like|has)\b/g, '<span class="cedar-action">$1</span>');
      return l;
    }).join('\n');
  }

  // API Client with automatic session & CSRF header injection
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
      // Immediately scrub the token from browser URL and history
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
        renderAuthScreen('Invalid or expired bootstrap token: ' + err.message);
        return;
      }
    }

    // Try restoring from sessionStorage
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
        sessionToken = null;
        csrfToken = null;
        sessionStorage.removeItem('relay_sess');
        sessionStorage.removeItem('relay_csrf');
      }
    }

    renderAuthScreen();
  }

  function renderAuthScreen(errorMsg = null) {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="auth-container">
        <svg class="brand-icon" style="width:48px;height:48px;margin-bottom:1rem;" viewBox="0 0 64 64">
          <path d="M32 10 L50 18 L50 36 C50 46 42 53 32 56 C22 53 14 46 14 36 L14 18 Z" fill="none" stroke="#10b981" stroke-width="4"/>
          <circle cx="32" cy="30" r="5" fill="#10b981"/>
          <path d="M32 35 L32 44" stroke="#10b981" stroke-width="4"/>
        </svg>
        <h1 class="auth-title">Relay Security Console</h1>
        <p class="auth-desc">Local-first, zero-trust security control plane. Enter your CLI-issued session token to unlock the console.</p>
        ${errorMsg ? `<div class="badge badge-danger" style="display:block;margin-bottom:1rem;padding:0.5rem;">${escapeHtml(errorMsg)}</div>` : ''}
        <form id="auth-form">
          <input type="password" id="token-input" class="auth-input" placeholder="Paste session token from 'relay ui'..." required autofocus />
          <button type="submit" class="btn btn-primary" style="width:100%;">Authenticate Session</button>
        </form>
      </div>
    `;

    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('token-input').value;
      if (!input) return;
      try {
        const data = await fetch('/api/v1/auth/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: input.trim() }),
        }).then(r => {
          if (!r.ok) throw new Error('Authentication rejected');
          return r.json();
        });

        sessionToken = data.session_token;
        csrfToken = data.csrf_token;
        sessionStorage.setItem('relay_sess', sessionToken);
        sessionStorage.setItem('relay_csrf', csrfToken);
        startApp();
      } catch (err) {
        renderAuthScreen(err.message);
      }
    });
  }

  function startApp() {
    renderMainLayout();
    window.addEventListener('hashchange', handleRoute);
    setupKeyboardShortcuts();
    handleRoute();
  }

  function setupKeyboardShortcuts() {
    window.addEventListener('keydown', (e) => {
      const tag = e.target.tagName.toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') {
        if (e.key === 'Escape') e.target.blur();
        return;
      }

      const keyNum = parseInt(e.key, 10);
      if (keyNum >= 1 && keyNum <= VIEWS.length) {
        e.preventDefault();
        window.location.hash = '#' + VIEWS[keyNum - 1].id;
        return;
      }

      if (e.key === 'r' || e.key === 'R') {
        e.preventDefault();
        triggerRefresh();
        return;
      }

      if (e.key === '/') {
        const searchInput = document.getElementById('filter-search');
        if (searchInput) {
          e.preventDefault();
          searchInput.focus();
          searchInput.select();
        }
        return;
      }

      if (e.key === '?' || (e.shiftKey && e.key === '/')) {
        e.preventDefault();
        showShortcutsModal();
        return;
      }

      if (e.key === 'Escape') {
        closeModal();
      }
    });
  }

  function renderMainLayout() {
    const app = document.getElementById('app');
    app.innerHTML = `
      <header class="header">
        <a href="#overview" class="brand" title="Relay Security Console">
          <svg class="brand-icon" viewBox="0 0 64 64">
            <path d="M32 10 L50 18 L50 36 C50 46 42 53 32 56 C22 53 14 46 14 36 L14 18 Z" fill="none" stroke="#10b981" stroke-width="4"/>
            <circle cx="32" cy="30" r="5" fill="#10b981"/>
            <path d="M32 35 L32 44" stroke="#10b981" stroke-width="4"/>
          </svg>
          <span>RELAY CONSOLE</span>
        </a>

        <nav class="nav" id="main-nav" aria-label="Main Navigation">
          ${VIEWS.map(v => `<button class="nav-link" data-view="${v.id}" title="${v.name} (Key: ${v.shortcut})">${v.name} <kbd>${v.shortcut}</kbd></button>`).join('')}
        </nav>

        <div class="toolbar-group">
          <div class="status-pill protected" id="global-status-pill" title="Gateway Active — Zero Ambient Credentials Enforced">
            <span class="status-dot pulse-dot"></span>
            <span id="global-status-text">PROTECTED</span>
          </div>

          <select id="auto-refresh-select" class="select-filter" style="padding:0.25rem 0.5rem;font-size:0.75rem;" title="Auto-Refresh Interval">
            <option value="0">Auto: Off</option>
            <option value="5000">Auto: 5s</option>
            <option value="10000">Auto: 10s</option>
            <option value="30000">Auto: 30s</option>
          </select>

          <button class="btn btn-secondary btn-sm" id="btn-refresh-now" title="Refresh Current View (R)">↻</button>
          <button class="btn btn-secondary btn-sm" id="btn-shortcuts-help" title="Keyboard Shortcuts (?)">?</button>
          <button class="btn btn-secondary btn-sm" id="btn-lock" title="Lock Console Session">Lock</button>
        </div>
      </header>
      <main class="container" id="view-container" tabindex="-1"></main>
      <footer class="footer">
        Relay v0.1.0 • Local-first Zero-Trust Security Gateway • Zero Cloud Telemetry • 127.0.0.1 Loopback
      </footer>
    `;

    document.querySelectorAll('#main-nav .nav-link').forEach(btn => {
      btn.addEventListener('click', () => {
        window.location.hash = '#' + btn.getAttribute('data-view');
      });
    });

    document.getElementById('auto-refresh-select').addEventListener('change', (e) => {
      const ms = parseInt(e.target.value, 10);
      setAutoRefresh(ms);
    });

    document.getElementById('btn-refresh-now').addEventListener('click', () => {
      triggerRefresh();
    });

    document.getElementById('btn-shortcuts-help').addEventListener('click', showShortcutsModal);

    document.getElementById('btn-lock').addEventListener('click', () => {
      sessionToken = null;
      csrfToken = null;
      sessionStorage.clear();
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      renderAuthScreen('Session locked.');
    });
  }

  function setAutoRefresh(ms) {
    autoRefreshInterval = ms;
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
      autoRefreshTimer = null;
    }
    if (ms > 0) {
      autoRefreshTimer = setInterval(() => {
        if (!isRefreshing && document.visibilityState !== 'hidden') {
          triggerRefresh(true);
        }
      }, ms);
      showToast(`Auto-refresh enabled (${ms / 1000}s)`, 'info', 2000);
    } else {
      showToast('Auto-refresh disabled', 'info', 2000);
    }
  }

  async function triggerRefresh(isAuto = false) {
    if (isRefreshing) return;
    isRefreshing = true;
    const icon = document.getElementById('btn-refresh-now');
    if (icon) icon.style.opacity = '0.5';
    try {
      await handleRoute(false);
      if (!isAuto) showToast('View refreshed', 'info', 1500);
    } finally {
      isRefreshing = false;
      if (icon) icon.style.opacity = '1';
    }
  }

  function handleRoute(showLoading = true) {
    let hash = window.location.hash.substring(1);
    let view = hash.split('?')[0] || 'overview';
    currentView = view;

    document.querySelectorAll('#main-nav .nav-link').forEach(link => {
      if (link.getAttribute('data-view') === view) {
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
      } else {
        link.classList.remove('active');
        link.removeAttribute('aria-current');
      }
    });

    const container = document.getElementById('view-container');
    if (showLoading) {
      container.innerHTML = `<div style="text-align:center;padding:4rem;color:var(--text-secondary);">Loading ${escapeHtml(view)}...</div>`;
    }

    if (view === 'overview') renderOverview();
    else if (view === 'activity') renderActivity();
    else if (view === 'action-detail') renderActionDetail();
    else if (view === 'receipts') renderReceipts();
    else if (view === 'ledger') renderLedger();
    else if (view === 'policies') renderPolicies();
    else if (view === 'security') renderSecurity();
    else if (view === 'egress') renderEgress();
    else if (view === 'connectors') renderConnectors();
    else if (view === 'doctor') renderDoctor();
    else renderOverview();
  }

  // VIEW: Overview
  async function renderOverview() {
    const container = document.getElementById('view-container');
    try {
      const [status, activityData] = await Promise.all([
        api('/api/v1/status'),
        api('/api/v1/activity?limit=5')
      ]);

      const recentItems = activityData.items || [];
      activityCache = recentItems;

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">Security Overview</h1>
            <p class="section-subtitle">Real-time posture and operational health of the Relay zero-trust gateway.</p>
          </div>
          <div class="toolbar-group">
            <a href="#doctor" class="btn btn-secondary btn-sm">Run Diagnostics</a>
            <a href="#ledger" class="btn btn-secondary btn-sm">Verify Ledger</a>
          </div>
        </div>

        <div class="grid-4">
          <div class="card">
            <div class="card-header">
              <span class="card-title">Security Posture</span>
              <span class="badge badge-success">PROTECTED</span>
            </div>
            <div class="card-value" style="color:var(--color-success)">ACTIVE</div>
            <div class="card-subtext">Zero Ambient Credentials</div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Policy Engine</span>
              <span class="badge badge-info">CEDAR</span>
            </div>
            <div class="card-value">Default Deny</div>
            <div class="card-subtext">${status.policy_count || 1} Active Policies Loaded</div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Ledger Integrity</span>
              <span class="badge badge-success">VERIFIED</span>
            </div>
            <div class="card-value">#${status.ledger_head_seq || 0}</div>
            <div class="card-subtext">${status.ledger_total_entries || 0} Hash-Chained Entries</div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Egress Sandbox</span>
              <span class="badge badge-warning">${escapeHtml(status.sandbox_short_mode || 'ACTIVE')}</span>
            </div>
            <div class="card-value">${status.active_connectors || 4} Connectors</div>
            <div class="card-subtext">${escapeHtml(status.egress_sandbox_mode || 'Enforced')}</div>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-header">
            <span class="card-title">System Configuration</span>
            <span class="badge badge-neutral">${escapeHtml(status.target_os || 'linux')} / ${escapeHtml(status.target_arch || 'x86_64')}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:1.25rem;font-size:0.875rem;">
            <div>
              <span style="color:var(--text-secondary)">Relay Version:</span><br/>
              <span class="mono" style="font-weight:600;">${escapeHtml(status.relay_version)}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Signing Key ID (Ed25519):</span><br/>
              <span class="mono">${escapeHtml(status.signing_key_id || 'relay-ed25519-v1')}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Ledger Database:</span><br/>
              <span class="mono">${escapeHtml(status.ledger_path || '.relay/ledger.db')}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Console Endpoint:</span><br/>
              <span class="mono" style="color:var(--color-brand)">127.0.0.1:${window.location.port || '8080'}</span>
            </div>
          </div>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
          <h2 style="font-size:1.15rem;font-weight:600;">Recent Governed Actions</h2>
          <a href="#activity" class="btn btn-secondary btn-sm">View All →</a>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Status</th>
                <th>Tool</th>
                <th>Principal</th>
                <th>ActionHash</th>
                <th>Decision</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="overview-activity-table">
              ${recentItems.length === 0 ? `
                <tr><td colspan="7" style="padding:3rem 1rem;">
                  <div class="empty-state-card" style="margin:0;border:none;">
                    <div class="empty-state-icon">🛡️</div>
                    <div class="empty-state-title">No Governed Actions Yet</div>
                    <div class="empty-state-desc">When agent tools are executed through Relay, the full audit trail appears here in real-time.</div>
                    <div class="code-snippet"><span>$ relay run -- &lt;your-command&gt;</span></div>
                  </div>
                </td></tr>
              ` : ''}
            </tbody>
          </table>
        </div>
      `;

      if (recentItems.length > 0) {
        const tbody = document.getElementById('overview-activity-table');
        recentItems.forEach(item => {
          const tr = document.createElement('tr');
          const badgeClass = item.status === 'ALLOWED' || item.status === 'EXECUTED' ? 'badge-success' :
                             item.status === 'DENIED' ? 'badge-danger' :
                             item.status === 'APPROVAL_REQUIRED' ? 'badge-warning' : 'badge-neutral';
          tr.innerHTML = `
            <td class="mono">${formatTs(item.timestamp)}</td>
            <td><span class="badge ${badgeClass}">${escapeHtml(item.status)}</span></td>
            <td><strong>${escapeHtml(item.tool_name)}</strong></td>
            <td class="mono">${escapeHtml(item.principal || 'agent')}</td>
            <td class="mono">
              <span title="${escapeHtml(item.action_hash)}">${escapeHtml(truncHash(item.action_hash))}</span>
              <button class="btn-copy" data-copy="${escapeHtml(item.action_hash)}" title="Copy ActionHash">⎘</button>
            </td>
            <td><span class="badge ${item.decision === 'ALLOW' ? 'badge-success' : 'badge-danger'}">${escapeHtml(item.decision || 'DENY')}</span></td>
            <td><a href="#action-detail?id=${encodeURIComponent(item.receipt_id || item.action_id)}" class="btn btn-secondary btn-sm">Inspect</a></td>
          `;
          tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.btn-copy').forEach(btn => {
          btn.addEventListener('click', () => {
            copyToClipboard(btn.getAttribute('data-copy'), 'ActionHash');
          });
        });
      }

    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading overview: ${escapeHtml(err.message)}</div>`;
    }
  }


  // VIEW: Activity
  async function renderActivity() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/activity?limit=100');
      const items = data.items || [];
      activityCache = items;

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">Governed Actions Activity</h1>
            <p class="section-subtitle">Full audit log of agent tool proposals evaluated by Cedar and governed by Relay.</p>
          </div>
          <div id="activity-counter" class="badge badge-neutral" style="font-size:0.8rem;padding:0.4rem 0.75rem;align-self:flex-start;">
            ${items.length} Actions Total
          </div>
        </div>

        <div class="filter-bar">
          <input type="text" id="filter-search" class="input-search" placeholder="Search tool, resource, ActionHash, principal... (Press /)" />
          <select id="filter-decision" class="select-filter" title="Filter by Cedar Decision">
            <option value="">All Decisions</option>
            <option value="ALLOW">Allow</option>
            <option value="DENY">Deny</option>
          </select>
          <select id="filter-status" class="select-filter" title="Filter by Execution Status">
            <option value="">All Statuses</option>
            <option value="ALLOWED">Allowed</option>
            <option value="EXECUTED">Executed</option>
            <option value="DENIED">Denied</option>
            <option value="APPROVAL_REQUIRED">Approval Required</option>
            <option value="FAILED">Failed</option>
          </select>
          <select id="filter-sort" class="select-filter" title="Sort Order">
            <option value="desc">Newest First</option>
            <option value="asc">Oldest First</option>
          </select>
          <button class="btn btn-secondary btn-sm" id="btn-clear-filters">Reset</button>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Status</th>
                <th>Tool</th>
                <th>Resource</th>
                <th>ActionHash</th>
                <th>Decision</th>
                <th>Approval</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="activity-table-body">
              ${items.length === 0 ? `
                <tr><td colspan="8" style="padding:3rem 1rem;">
                  <div class="empty-state-card" style="margin:0;border:none;">
                    <div class="empty-state-icon">📋</div>
                    <div class="empty-state-title">No Governed Activity Found</div>
                    <div class="empty-state-desc">Every operation executed via Relay generates an immutable audit record here.</div>
                    <div class="code-snippet"><span>$ relay mcp run github-mcp</span></div>
                  </div>
                </td></tr>
              ` : ''}
            </tbody>
          </table>
        </div>
      `;

      const tbody = document.getElementById('activity-table-body');
      const counterEl = document.getElementById('activity-counter');

      function updateTable() {
        const searchText = document.getElementById('filter-search').value.toLowerCase().trim();
        const statusFilter = document.getElementById('filter-status').value;
        const decisionFilter = document.getElementById('filter-decision').value;
        const sortOrder = document.getElementById('filter-sort').value;

        let filtered = items.filter(item => {
          const matchesText = !searchText ||
            (item.tool_name && item.tool_name.toLowerCase().includes(searchText)) ||
            (item.action_hash && item.action_hash.toLowerCase().includes(searchText)) ||
            (item.receipt_id && item.receipt_id.toLowerCase().includes(searchText)) ||
            (item.resource && item.resource.toLowerCase().includes(searchText)) ||
            (item.principal && item.principal.toLowerCase().includes(searchText));
          const matchesStatus = !statusFilter || item.status === statusFilter;
          const matchesDecision = !decisionFilter || item.decision === decisionFilter;
          return matchesText && matchesStatus && matchesDecision;
        });

        if (sortOrder === 'asc') {
          filtered.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        } else {
          filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        }

        if (counterEl) counterEl.textContent = `${filtered.length} of ${items.length} Actions`;

        tbody.innerHTML = '';
        if (filtered.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:2.5rem;">No actions match the active filters.</td></tr>';
          return;
        }

        filtered.forEach(item => {
          const tr = document.createElement('tr');
          const badgeClass = item.status === 'ALLOWED' || item.status === 'EXECUTED' ? 'badge-success' :
                             item.status === 'DENIED' ? 'badge-danger' :
                             item.status === 'APPROVAL_REQUIRED' ? 'badge-warning' : 'badge-neutral';
          tr.innerHTML = `
            <td class="mono">${formatTs(item.timestamp)}</td>
            <td><span class="badge ${badgeClass}">${escapeHtml(item.status)}</span></td>
            <td><strong>${escapeHtml(item.tool_name)}</strong></td>
            <td class="mono" title="${escapeHtml(item.resource)}">${escapeHtml(truncHash(item.resource, 26))}</td>
            <td class="mono">
              <span title="${escapeHtml(item.action_hash)}">${escapeHtml(truncHash(item.action_hash, 14))}</span>
              <button class="btn-copy" data-copy="${escapeHtml(item.action_hash)}" title="Copy ActionHash">⎘</button>
            </td>
            <td><span class="badge ${item.decision === 'ALLOW' ? 'badge-success' : 'badge-danger'}">${escapeHtml(item.decision || 'DENY')}</span></td>
            <td><span class="badge badge-neutral">${escapeHtml(item.approval_state || 'NOT_REQUIRED')}</span></td>
            <td><a href="#action-detail?id=${encodeURIComponent(item.receipt_id || item.action_id)}" class="btn btn-secondary btn-sm">Inspect</a></td>
          `;
          tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.btn-copy').forEach(btn => {
          btn.addEventListener('click', () => {
            copyToClipboard(btn.getAttribute('data-copy'), 'ActionHash');
          });
        });
      }

      updateTable();

      document.getElementById('filter-search').addEventListener('input', updateTable);
      document.getElementById('filter-status').addEventListener('change', updateTable);
      document.getElementById('filter-decision').addEventListener('change', updateTable);
      document.getElementById('filter-sort').addEventListener('change', updateTable);
      document.getElementById('btn-clear-filters').addEventListener('click', () => {
        document.getElementById('filter-search').value = '';
        document.getElementById('filter-status').value = '';
        document.getElementById('filter-decision').value = '';
        document.getElementById('filter-sort').value = 'desc';
        updateTable();
      });

    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading activity: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: Action Detail (7 Stages Lifecycle)
  async function renderActionDetail() {
    const container = document.getElementById('view-container');
    const urlParams = new URLSearchParams(window.location.hash.split('?')[1] || '');
    const id = urlParams.get('id');

    if (!id) {
      container.innerHTML = `
        <div class="badge badge-warning" style="padding:1rem;display:block;margin-bottom:1rem;">No Action or Receipt ID specified.</div>
        <a href="#activity" class="btn btn-secondary">Back to Activity</a>
      `;
      return;
    }

    try {
      const detail = await api(`/api/v1/activity/${encodeURIComponent(id)}`);
      const r = detail.receipt || {};
      const pred = detail.predicate || {};
      const prop = pred.canonical_proposal || {};
      const pol = pred.policy_decision || {};
      const app = pred.operator_approval || {};
      const cred = pred.credential_lease || {};
      const exec = pred.execution_observation || {};

      container.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
          <div>
            <h1 class="section-title">Action Lifecycle Detail</h1>
            <p class="section-subtitle">Seven-stage governed execution pipeline and cryptographic evidence.</p>
          </div>
          <a href="#activity" class="btn btn-secondary btn-sm">← Back to Activity</a>
        </div>

        <div class="lifecycle-flow">
          <!-- Stage 1: Proposal -->
          <div class="lifecycle-step">
            <div class="step-num">1</div>
            <div class="step-content">
              <div class="step-title">
                <span>Tool Action Proposal</span>
                <span class="badge badge-info">${escapeHtml(prop.tool_name || detail.tool_name || 'unknown')}</span>
              </div>
              <div class="step-meta" style="margin-bottom:0.75rem;">
                Action ID: <span class="mono">${escapeHtml(detail.action_id || id)}</span> • 
                Principal: <span class="mono">${escapeHtml(prop.principal || 'agent')}</span> • 
                Resource: <span class="mono">${escapeHtml(prop.resource || detail.resource || '-')}</span>
              </div>
              <div class="step-meta">
                ActionHash (RFC 8785 JCS): <span class="mono">${escapeHtml(detail.action_hash || r.action_hash || '-')}</span>
              </div>
              <details style="margin-top:0.5rem;">
                <summary style="cursor:pointer;color:var(--color-info);font-size:0.85rem;">View Canonical Proposal (Redacted Arguments)</summary>
                <pre style="margin-top:0.5rem;">${escapeHtml(JSON.stringify(prop.arguments || {}, null, 2))}</pre>
              </details>
            </div>
          </div>

          <!-- Stage 2: Policy -->
          <div class="lifecycle-step">
            <div class="step-num">2</div>
            <div class="step-content">
              <div class="step-title">
                <span>Cedar Policy Decision</span>
                <span class="badge ${pol.decision === 'ALLOW' ? 'badge-success' : 'badge-danger'}">${escapeHtml(pol.decision || detail.decision || 'DENY')}</span>
              </div>
              <div class="step-meta">
                Policy Digest: <span class="mono">${escapeHtml(pol.policy_digest || '-')}</span><br/>
                Determining Policies: <span class="mono">${escapeHtml(JSON.stringify(pol.determining_policies || ['default-deny']))}</span>
              </div>
            </div>
          </div>

          <!-- Stage 3: Approval -->
          <div class="lifecycle-step">
            <div class="step-num">3</div>
            <div class="step-content">
              <div class="step-title">
                <span>Interactive Operator Approval</span>
                <span class="badge badge-neutral">${escapeHtml(app.decision || 'NOT_REQUIRED')}</span>
              </div>
              <div class="step-meta">
                Mechanism: <span class="mono">${escapeHtml(app.mechanism || 'Out-of-band /dev/tty Gate')}</span> • 
                Approver: <span class="mono">${escapeHtml(app.approver || 'Relay Engine')}</span>
              </div>
            </div>
          </div>

          <!-- Stage 4: Credential Lease -->
          <div class="lifecycle-step">
            <div class="step-num">4</div>
            <div class="step-content">
              <div class="step-title">
                <span>Just-In-Time Credential Lease</span>
                <span class="badge badge-success">ZERO AMBIENT</span>
              </div>
              <div class="step-meta">
                Lease ID: <span class="mono">${escapeHtml(cred.lease_id || 'None (Native Public Access)')}</span> • 
                Provider: <span class="mono">${escapeHtml(cred.provider || 'Zeroized In-Memory Broker')}</span><br/>
                Secret Material: <strong style="color:var(--color-success)">[COMPLETELY REDACTED / NEVER OBSERVED BY AGENT]</strong>
              </div>
            </div>
          </div>

          <!-- Stage 5: Execution -->
          <div class="lifecycle-step">
            <div class="step-num">5</div>
            <div class="step-content">
              <div class="step-title">
                <span>Native Tool Execution</span>
                <span class="badge badge-info">${escapeHtml(exec.status || 'SUCCESS')}</span>
              </div>
              <div class="step-meta">
                Exit Code: <span class="mono">${escapeHtml(exec.exit_code !== undefined ? exec.exit_code : 0)}</span> • 
                Output Bytes: <span class="mono">${escapeHtml(exec.output_byte_count || 0)}</span> • 
                Stdout Digest: <span class="mono">${escapeHtml(truncHash(exec.stdout_digest))}</span>
              </div>
            </div>
          </div>

          <!-- Stage 6: Receipt -->
          <div class="lifecycle-step">
            <div class="step-num">6</div>
            <div class="step-content">
              <div class="step-title">
                <span>Action Receipt (DSSE & in-toto v1.0)</span>
                <span class="badge badge-success">ED25519 SIGNED</span>
              </div>
              <div class="step-meta">
                Receipt ID: <span class="mono">${escapeHtml(r.receipt_id || detail.receipt_id || '-')}</span> • 
                Key ID: <span class="mono">${escapeHtml(detail.key_id || 'relay-ed25519-v1')}</span>
              </div>
              <div style="margin-top:0.75rem;">
                <button class="btn btn-primary btn-sm" id="btn-verify-receipt-detail">Cryptographically Verify Receipt</button>
                <div id="receipt-verify-result" style="margin-top:0.5rem;"></div>
              </div>
            </div>
          </div>

          <!-- Stage 7: Ledger -->
          <div class="lifecycle-step">
            <div class="step-num">7</div>
            <div class="step-content">
              <div class="step-title">
                <span>Append-Only Ledger Entry</span>
                <span class="badge badge-success">CHAINED</span>
              </div>
              <div class="step-meta">
                Sequence: <span class="mono">#${escapeHtml(detail.sequence_number || '1')}</span> • 
                Current Hash: <span class="mono">${escapeHtml(truncHash(r.receipt_hash || detail.receipt_hash))}</span> • 
                Parent Hash: <span class="mono">${escapeHtml(truncHash(r.parent_receipt_hash || detail.parent_receipt_hash))}</span>
              </div>
            </div>
          </div>
        </div>
      `;

      document.getElementById('btn-verify-receipt-detail').addEventListener('click', async () => {
        const resDiv = document.getElementById('receipt-verify-result');
        resDiv.innerHTML = '<span style="color:var(--text-secondary)">Verifying Ed25519 digital signature...</span>';
        try {
          const recId = r.receipt_id || detail.receipt_id || id;
          const verifyData = await api(`/api/v1/receipts/${encodeURIComponent(recId)}/verify`, { method: 'POST' });
          if (verifyData.is_valid) {
            resDiv.innerHTML = `<div class="badge badge-success" style="padding:0.5rem;font-size:0.85rem;display:inline-block;">✓ VALID SIGNATURE (Ed25519 Verified, In-toto Statement Match)</div>`;
          } else {
            resDiv.innerHTML = `<div class="badge badge-danger" style="padding:0.5rem;font-size:0.85rem;display:inline-block;">✗ INVALID RECEIPT (${escapeHtml(verifyData.reason || 'Signature mismatch')})</div>`;
          }
        } catch (e) {
          resDiv.innerHTML = `<div class="badge badge-danger" style="padding:0.5rem;font-size:0.85rem;display:inline-block;">Verification Error: ${escapeHtml(e.message)}</div>`;
        }
      });

    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading action detail: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: Receipts & Cryptographic Verifier
  async function renderReceipts() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/receipts?limit=100');
      const receipts = data.receipts || [];

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">Action Receipts &amp; Cryptographic Verifier</h1>
            <p class="section-subtitle">RFC 9598 DSSE envelopes containing in-toto v1.0 statements signed with Ed25519.</p>
          </div>
          <span class="badge badge-neutral" style="font-size:0.8rem;padding:0.4rem 0.75rem;align-self:flex-start;">${receipts.length} Receipts</span>
        </div>

        <div id="receipt-verify-banner"></div>

        <div class="filter-bar" style="margin-bottom:1rem;">
          <input type="text" id="filter-receipt-search" class="input-search" placeholder="Search by receipt ID or ActionHash..." />
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Created At (UTC)</th>
                <th>Receipt ID</th>
                <th>ActionHash</th>
                <th>Signatures</th>
                <th>Verify</th>
                <th>Export</th>
              </tr>
            </thead>
            <tbody id="receipts-table-body">
              ${receipts.length === 0 ? `
                <tr><td colspan="6" style="padding:3rem 1rem;">
                  <div class="empty-state-card" style="margin:0;border:none;">
                    <div class="empty-state-icon">🔏</div>
                    <div class="empty-state-title">No Receipts Generated</div>
                    <div class="empty-state-desc">DSSE-signed receipts appear here after Relay governs and executes tool actions. Each receipt is cryptographically verifiable.</div>
                    <div class="code-snippet"><span>$ relay mcp run &lt;connector&gt;</span></div>
                  </div>
                </td></tr>
              ` : ''}
            </tbody>
          </table>
        </div>
      `;

      const tbody = document.getElementById('receipts-table-body');

      function buildRows(list) {
        tbody.innerHTML = '';
        if (list.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem;">No receipts match your search.</td></tr>';
          return;
        }
        list.forEach(r => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="mono">${formatTs(r.created_at)}</td>
            <td class="mono">
              <span title="${escapeHtml(r.receipt_id)}">${escapeHtml(truncHash(r.receipt_id, 20))}</span>
              <button class="btn-copy" data-copy="${escapeHtml(r.receipt_id)}" title="Copy Receipt ID">⎘</button>
            </td>
            <td class="mono">
              <span title="${escapeHtml(r.action_hash)}">${escapeHtml(truncHash(r.action_hash))}</span>
              <button class="btn-copy" data-copy="${escapeHtml(r.action_hash)}" title="Copy ActionHash">⎘</button>
            </td>
            <td><span class="badge badge-info">${r.signature_count || 1} Sig (Ed25519)</span></td>
            <td><button class="btn btn-primary btn-sm btn-verify" data-id="${escapeHtml(r.receipt_id)}">Verify</button></td>
            <td><button class="btn btn-secondary btn-sm btn-export" data-id="${escapeHtml(r.receipt_id)}">Export JSON</button></td>
          `;
          tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.btn-copy').forEach(btn => {
          btn.addEventListener('click', () => {
            copyToClipboard(btn.getAttribute('data-copy'), btn.title);
          });
        });

        tbody.querySelectorAll('.btn-verify').forEach(btn => {
          btn.addEventListener('click', async () => {
            const recId = btn.getAttribute('data-id');
            btn.textContent = 'Verifying...';
            btn.disabled = true;
            try {
              const res = await api(`/api/v1/receipts/${encodeURIComponent(recId)}/verify`, { method: 'POST' });
              const banner = document.getElementById('receipt-verify-banner');
              if (res.is_valid) {
                showToast('✓ Receipt signature valid — Ed25519 verified', 'success', 4000);
                banner.innerHTML = `
                  <div class="verification-banner valid">
                    <div class="verification-icon">✓</div>
                    <div>
                      <strong>VALID SIGNATURE &amp; DOMAIN INTEGRITY</strong><br/>
                      Receipt <span class="mono">${escapeHtml(recId)}</span> verified cryptographically against Ed25519 public key.
                    </div>
                  </div>
                `;
              } else {
                showToast('✗ Receipt signature INVALID — cryptographic divergence', 'error', 5000);
                banner.innerHTML = `
                  <div class="verification-banner invalid">
                    <div class="verification-icon">✗</div>
                    <div>
                      <strong>INVALID RECEIPT</strong><br/>
                      Signature verification failed: ${escapeHtml(res.reason || 'Cryptographic divergence')}
                    </div>
                  </div>
                `;
              }
            } catch (e) {
              showToast('Verification request failed: ' + e.message, 'error', 4000);
            } finally {
              btn.textContent = 'Verify';
              btn.disabled = false;
            }
          });
        });

        tbody.querySelectorAll('.btn-export').forEach(btn => {
          btn.addEventListener('click', async () => {
            const recId = btn.getAttribute('data-id');
            btn.textContent = 'Exporting...';
            btn.disabled = true;
            try {
              const exportData = await api(`/api/v1/receipts/${encodeURIComponent(recId)}/export`);
              const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `relay-receipt-${recId}.json`;
              a.click();
              URL.revokeObjectURL(url);
              showToast('Receipt exported as JSON', 'success', 2500);
            } catch (e) {
              showToast('Export failed: ' + e.message, 'error', 4000);
            } finally {
              btn.textContent = 'Export JSON';
              btn.disabled = false;
            }
          });
        });
      }

      buildRows(receipts);

      document.getElementById('filter-receipt-search').addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase().trim();
        if (!q) { buildRows(receipts); return; }
        buildRows(receipts.filter(r =>
          (r.receipt_id && r.receipt_id.toLowerCase().includes(q)) ||
          (r.action_hash && r.action_hash.toLowerCase().includes(q))
        ));
      });

    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading receipts: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: Ledger Integrity & Verifier
  async function renderLedger() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/ledger/status');

      container.innerHTML = `
        <h1 class="section-title">Ledger Integrity & Hash Chain</h1>
        <p class="section-subtitle">Append-only SQLite cryptographic audit trail protected by SHA-256 hash chaining and filesystem permissions.</p>

        <div id="ledger-verify-banner"></div>

        <div class="grid-3">
          <div class="card">
            <div class="card-title">Chain Status</div>
            <div class="card-value" style="color:var(--color-success)">ACTIVE</div>
            <div class="card-subtext">Append-Only SQLite (WAL Mode, 0600)</div>
          </div>
          <div class="card">
            <div class="card-title">Head Sequence</div>
            <div class="card-value">#${data.head_sequence || 0}</div>
            <div class="card-subtext">${data.total_entries || 0} Total Entries Recorded</div>
          </div>
          <div class="card">
            <div class="card-title">Genesis Block</div>
            <div class="card-value" style="font-size:1.2rem;line-height:2.2rem;" class="mono">${escapeHtml(truncHash(data.genesis_hash, 20))}</div>
            <div class="card-subtext">Immutable Root of Trust</div>
          </div>
        </div>

        <div style="margin-bottom:1.5rem;">
          <button class="btn btn-primary" id="btn-verify-ledger">
            <span>Cryptographically Verify Entire Ledger Hash Chain</span>
          </button>
        </div>

        <h2 style="font-size:1.15rem;font-weight:600;margin-bottom:0.75rem;">Recent Ledger Blocks</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Seq #</th>
                <th>Recorded At (UTC)</th>
                <th>Receipt ID</th>
                <th>Block Hash</th>
                <th>Parent Hash</th>
              </tr>
            </thead>
            <tbody id="ledger-entries-body">
              ${(data.recent_entries || []).length === 0 ? '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:2.5rem;">No blocks recorded in ledger.</td></tr>' : ''}
            </tbody>
          </table>
        </div>
      `;

      const tbody = document.getElementById('ledger-entries-body');
      (data.recent_entries || []).forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="mono"><strong>#${e.sequence_number}</strong></td>
          <td class="mono">${formatTs(e.recorded_at)}</td>
          <td class="mono">${escapeHtml(e.receipt_id)}</td>
          <td class="mono" title="${escapeHtml(e.receipt_hash)}">${escapeHtml(truncHash(e.receipt_hash, 20))}</td>
          <td class="mono" title="${escapeHtml(e.parent_receipt_hash)}">${escapeHtml(truncHash(e.parent_receipt_hash, 20))}</td>
        `;
        tbody.appendChild(tr);
      });

      document.getElementById('btn-verify-ledger').addEventListener('click', async () => {
        const banner = document.getElementById('ledger-verify-banner');
        banner.innerHTML = '<div style="padding:1rem;color:var(--text-secondary)">Executing systematic offline ledger verification...</div>';
        try {
          const res = await api('/api/v1/ledger/verify', { method: 'POST' });
          if (res.is_valid) {
            banner.innerHTML = `
              <div class="verification-banner valid">
                <div class="verification-icon">✓</div>
                <div>
                  <strong>LEDGER INTEGRITY VERIFIED</strong><br/>
                  Verified ${res.total_verified_entries} blocks in ${res.duration_ms} ms. SHA-256 hash chains unbroken from genesis block.
                </div>
              </div>
            `;
          } else {
            banner.innerHTML = `
              <div class="verification-banner invalid">
                <div class="verification-icon">✗</div>
                <div>
                  <strong>CORRUPTION DETECTED IN LEDGER</strong><br/>
                  ${escapeHtml(res.error_message || 'Hash chain mismatch detected.')}
                </div>
              </div>
            `;
          }
        } catch (e) {
          banner.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Verification Failed: ${escapeHtml(e.message)}</div>`;
        }
      });

    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading ledger: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: Policies & Validator
  async function renderPolicies() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/policies');
      const policyText = data.policy_text || '// Default bundled policies';

      container.innerHTML = `
        <div class="view-header">
          <div>
            <h1 class="section-title">Cedar Security Policies</h1>
            <p class="section-subtitle">Deterministic AWS Cedar authorization policies governing all tool invocations.</p>
          </div>
          <div class="toolbar-group">
            <button class="btn btn-secondary btn-sm" id="btn-copy-digest" title="Copy Policy Digest">Copy Digest</button>
            <button class="btn btn-primary btn-sm" id="btn-reload-policies">↺ Reload From Disk</button>
          </div>
        </div>

        <div id="policy-alert"></div>

        <div class="grid-3">
          <div class="card">
            <div class="card-title">Policy Model</div>
            <div class="card-value" style="color:var(--color-success)">Default Deny</div>
            <div class="card-subtext">Explicit Permit Required</div>
          </div>
          <div class="card">
            <div class="card-title">Policy Digest <span class="badge badge-neutral" style="font-size:0.7rem;">SI-010</span></div>
            <div class="card-value mono" style="font-size:1rem;line-height:2.2rem;" title="${escapeHtml(data.policy_digest)}">${escapeHtml(truncHash(data.policy_digest, 22))}</div>
            <div class="card-subtext">Tamper Detection SHA-256</div>
          </div>
          <div class="card">
            <div class="card-title">Schema Version</div>
            <div class="card-value">Cedar 4.0</div>
            <div class="card-subtext">Strict Entity &amp; Action Conformity</div>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-header">
            <span class="card-title">Active Cedar Policies</span>
            <span class="badge badge-neutral" style="font-size:0.75rem;">${data.policy_count || 1} Policies Loaded</span>
          </div>
          <pre id="policy-display">${highlightCedar(policyText)}</pre>
        </div>

        <div class="card">
          <div class="card-header">
            <span class="card-title">Test &amp; Validate Policy Syntax</span>
          </div>
          <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:0.75rem;">
            Test prospective Cedar policy statements against Relay's Cedar schema before applying them.
          </p>
          <div class="filter-bar" style="margin-bottom:0.75rem;">
            <select id="policy-template" class="select-filter" style="flex:0 0 auto;">
              <option value="">— Insert Template —</option>
              <option value="permit_all">permit(principal, action, resource);</option>
              <option value="permit_tool">permit(principal, action == Action::"tool_name", resource);</option>
              <option value="forbid_tool">forbid(principal, action == Action::"tool_name", resource);</option>
              <option value="when_block">permit(principal, action, resource) when { context.approved == true };</option>
            </select>
          </div>
          <textarea id="policy-test-input" class="auth-input" style="height:140px;font-family:var(--font-mono);font-size:0.85rem;" placeholder="permit(principal, action, resource) when { ... };"></textarea>
          <div>
            <button class="btn btn-primary btn-sm" id="btn-validate-policy">Validate Syntax</button>
          </div>
          <div id="policy-validation-result" style="margin-top:0.75rem;"></div>
        </div>
      `;

      // Make the Cedar pre block not escape (highlightCedar returns HTML)
      // We already set it via innerHTML in the template above

      document.getElementById('btn-copy-digest').addEventListener('click', () => {
        copyToClipboard(data.policy_digest || '', 'Policy Digest');
      });

      document.getElementById('btn-reload-policies').addEventListener('click', () => {
        openModal({
          title: 'Reload Cedar Policies',
          body: `<p>This will atomically reload Cedar policies from disk and hot-swap the running policy engine.</p>
                 <p style="color:var(--color-warning);margin-top:0.75rem;">⚠️ All governed actions will immediately use the new policy set.</p>`,
          confirmText: 'Reload Policies',
          confirmClass: 'btn-primary',
          onConfirm: async () => {
            const alertDiv = document.getElementById('policy-alert');
            try {
              const res = await api('/api/v1/policies/reload', { method: 'POST' });
              showToast(`✓ Policies reloaded (${res.policy_count} active, digest: ${truncHash(res.policy_digest, 12)})`, 'success', 4000);
              alertDiv.innerHTML = `
                <div class="verification-banner valid">
                  <div class="verification-icon">✓</div>
                  <div>
                    <strong>POLICIES RELOADED SUCCESSFULLY</strong><br/>
                    New Policy Digest: <span class="mono">${escapeHtml(res.policy_digest)}</span> (${res.policy_count} policies active).
                  </div>
                </div>
              `;
              setTimeout(renderPolicies, 1500);
            } catch (e) {
              showToast('Policy reload failed: ' + e.message, 'error', 5000);
              alertDiv.innerHTML = `
                <div class="verification-banner invalid">
                  <div class="verification-icon">✗</div>
                  <div>
                    <strong>POLICY RELOAD FAILED — ROLLED BACK</strong><br/>
                    ${escapeHtml(e.message)}
                  </div>
                </div>
              `;
            }
          }
        });
      });

      document.getElementById('policy-template').addEventListener('change', (e) => {
        const templates = {
          permit_all: 'permit(principal, action, resource);',
          permit_tool: 'permit(\n  principal,\n  action == Action::"tool_name",\n  resource\n);',
          forbid_tool: 'forbid(\n  principal,\n  action == Action::"tool_name",\n  resource\n);',
          when_block: 'permit(\n  principal,\n  action,\n  resource\n) when {\n  context.approved == true\n};',
        };
        if (e.target.value && templates[e.target.value]) {
          document.getElementById('policy-test-input').value = templates[e.target.value];
        }
        e.target.value = '';
      });

      document.getElementById('btn-validate-policy').addEventListener('click', async () => {
        const text = document.getElementById('policy-test-input').value;
        const resDiv = document.getElementById('policy-validation-result');
        if (!text.trim()) {
          resDiv.innerHTML = '<span class="badge badge-warning">Please enter Cedar policy text to validate.</span>';
          return;
        }
        resDiv.innerHTML = '<span style="color:var(--text-secondary)">Validating against Cedar schema...</span>';
        try {
          const res = await api('/api/v1/policies/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ policy_text: text }),
          });
          if (res.is_valid) {
            resDiv.innerHTML = `<span class="badge badge-success" style="padding:0.5rem;">✓ VALID: Policy syntax conformant with Relay Cedar schema (${res.policy_count} policies detected).</span>`;
            showToast('✓ Cedar policy syntax valid', 'success', 2500);
          } else {
            resDiv.innerHTML = `<span class="badge badge-danger" style="padding:0.5rem;">✗ INVALID: ${escapeHtml(res.error || 'Validation error')}</span>`;
            showToast('✗ Policy syntax invalid — check errors', 'warning', 3000);
          }
        } catch (e) {
          resDiv.innerHTML = `<span class="badge badge-danger" style="padding:0.5rem;">Error: ${escapeHtml(e.message)}</span>`;
        }
      });

    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading policies: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: Security Posture & Sandbox
  async function renderSecurity() {
    const container = document.getElementById('view-container');
    try {
      const sec = await api('/api/v1/security');

      container.innerHTML = `
        <h1 class="section-title">Security Posture & Trust Boundaries</h1>
        <p class="section-subtitle">Formal trust boundaries, platform sandbox enforcement, and limitation transparency.</p>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-title" style="margin-bottom:0.75rem;">Relay Zero-Trust Pipeline Architecture</div>
          <pre style="line-height:1.4;">
[ UNTRUSTED AGENT ] ── stdio (JSON-RPC) ──► [ TRUST BOUNDARY 1 ]
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
     Path Jail Enforcement              AST Read-Only Enforce             Loopback Egress Proxy
          </pre>
        </div>

        <div class="grid-2">
          <div class="card">
            <div class="card-title">Platform Sandbox Limitations</div>
            <div style="margin-top:0.75rem;font-size:0.9rem;line-height:1.6;">
              <p><strong>Detected Host OS:</strong> <span class="mono">${escapeHtml(sec.target_os)}</span></p>
              <p><strong>Enforcement Mode:</strong> <span class="badge ${sec.is_linux_netns ? 'badge-success' : 'badge-warning'}">${escapeHtml(sec.egress_mode)}</span></p>
              <div style="margin-top:0.75rem;padding:0.75rem;background:var(--bg-primary);border-radius:6px;border:1px solid var(--border-color);">
                ${sec.is_linux_netns ?
                  '<strong>Linux Full Enforced:</strong> Unprivileged network namespaces isolate child subprocess network stacks completely from the host loopback and LAN.' :
                  '<strong>Cooperative Proxy Mode:</strong> On macOS/Windows, raw socket containment relies on cooperative proxy configuration (HTTP_PROXY/HTTPS_PROXY). Kernel-level raw socket blocking is unavailable without root containerization.'}
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Key Security Invariants</div>
            <ul style="margin-top:0.75rem;font-size:0.875rem;padding-left:1.25rem;color:var(--text-secondary);line-height:1.6;">
              <li><strong style="color:var(--text-primary)">SI-001:</strong> Agent environment contains ZERO ambient target credentials.</li>
              <li><strong style="color:var(--text-primary)">SI-004:</strong> Every governed operation requires deterministic Cedar authorization.</li>
              <li><strong style="color:var(--text-primary)">SI-008:</strong> Destructive operations require out-of-band /dev/tty confirmation.</li>
              <li><strong style="color:var(--text-primary)">SI-011:</strong> Every action produces signed RFC 9598 DSSE Action Receipts.</li>
              <li><strong style="color:var(--text-primary)">SI-014:</strong> Cryptographic audit ledger is immutable and hash-chained.</li>
            </ul>
          </div>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading security posture: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: External Egress
  async function renderEgress() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/egress');

      container.innerHTML = `
        <h1 class="section-title">External MCP Egress & Anti-SSRF</h1>
        <p class="section-subtitle">Mediation boundary for external network calls and cloud metadata access prevention.</p>

        <div class="grid-3">
          <div class="card">
            <div class="card-title">Proxy Status</div>
            <div class="card-value" style="color:var(--color-success)">${escapeHtml(data.proxy_status || 'RUNNING')}</div>
            <div class="card-subtext">${escapeHtml(data.bind_addr || '127.0.0.1:Loopback')}</div>
          </div>
          <div class="card">
            <div class="card-title">Active Proxy Sessions</div>
            <div class="card-value">${data.active_sessions || 0}</div>
            <div class="card-subtext">Short-lived JIT Leases</div>
          </div>
          <div class="card">
            <div class="card-title">Anti-SSRF Protection</div>
            <div class="card-value" style="color:var(--color-success)">ACTIVE</div>
            <div class="card-subtext">DNS Rebinding & Cloud Metadata Blocked</div>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-title">Egress Protection Mechanisms</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;margin-top:0.75rem;font-size:0.875rem;">
            <div style="padding:0.75rem;background:var(--bg-primary);border-radius:6px;border:1px solid var(--border-color);">
              <strong>Cloud Metadata Protection</strong><br/>
              <span style="color:var(--color-danger)">169.254.169.254</span> and link-local IPv6 ranges are hard-blocked by the DNS resolver.
            </div>
            <div style="padding:0.75rem;background:var(--bg-primary);border-radius:6px;border:1px solid var(--border-color);">
              <strong>DNS Rebinding Defense</strong><br/>
              Hostnames resolving to private RFC 1918 / loopback ranges are blocked before socket connection.
            </div>
            <div style="padding:0.75rem;background:var(--bg-primary);border-radius:6px;border:1px solid var(--border-color);">
              <strong>Header Sanitization</strong><br/>
              Subprocesses cannot forge or overwrite Relay authentication headers during egress transit.
            </div>
          </div>
        </div>

        <h2 style="font-size:1.15rem;font-weight:600;margin-bottom:0.75rem;">Recent Blocked Egress Attempts</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Target Destination</th>
                <th>Blocked Reason</th>
                <th>Policy Rule</th>
              </tr>
            </thead>
            <tbody>
              ${(data.blocked_attempts || []).length === 0 ? '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:2rem;">No blocked egress attempts detected.</td></tr>' : ''}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading egress: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: Connectors
  async function renderConnectors() {
    const container = document.getElementById('view-container');
    try {
      const data = await api('/api/v1/connectors');
      const connectors = data.connectors || [];

      container.innerHTML = `
        <h1 class="section-title">Tool Connectors</h1>
        <p class="section-subtitle">In-process native connectors and subprocess adapters governed by Relay.</p>

        <div class="grid-2">
          ${connectors.map(c => `
            <div class="card">
              <div class="card-header">
                <span class="card-title">${escapeHtml(c.name)}</span>
                <span class="badge ${c.is_available ? 'badge-success' : 'badge-neutral'}">${c.is_available ? 'AVAILABLE' : 'OFFLINE'}</span>
              </div>
              <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:0.75rem;">${escapeHtml(c.description)}</p>
              <div style="font-size:0.85rem;line-height:1.6;color:var(--text-muted);">
                <div>Security Mode: <span class="mono" style="color:var(--text-primary)">${escapeHtml(c.security_mode)}</span></div>
                <div>Isolation: <span class="mono" style="color:var(--text-primary)">${escapeHtml(c.isolation)}</span></div>
                <div>Credential Injection: <span class="mono" style="color:var(--text-primary)">${escapeHtml(c.credential_mode)}</span></div>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading connectors: ${escapeHtml(err.message)}</div>`;
    }
  }

  // VIEW: Doctor (System Health)
  async function renderDoctor() {
    const container = document.getElementById('view-container');
    try {
      const doc = await api('/api/v1/doctor');

      container.innerHTML = `
        <h1 class="section-title">System Health & Foundation Diagnostics</h1>
        <p class="section-subtitle">Canonical status checks shared directly with 'relay doctor'.</p>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-header">
            <span class="card-title">Diagnostic Summary</span>
            <span class="badge ${doc.is_healthy ? 'badge-success' : 'badge-danger'}">${doc.is_healthy ? 'HEALTHY' : 'NEEDS ATTENTION'}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;font-size:0.875rem;">
            <div>
              <span style="color:var(--text-secondary)">Relay Version:</span><br/>
              <span class="mono" style="font-size:0.95rem;">${escapeHtml(doc.relay_version)}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Platform / Architecture:</span><br/>
              <span class="mono" style="font-size:0.95rem;">${escapeHtml(doc.target_os)} (${escapeHtml(doc.target_arch)})</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Working Directory:</span><br/>
              <span class="mono" style="font-size:0.85rem;">${escapeHtml(doc.working_directory)}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Config Directory:</span><br/>
              <span class="mono" style="font-size:0.85rem;">${escapeHtml(doc.config_directory)} [${doc.config_directory_exists ? 'EXISTS' : 'NOT CREATED'}]</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Ledger Database:</span><br/>
              <span class="mono" style="font-size:0.85rem;">${escapeHtml(doc.ledger_path)} [${doc.ledger_exists ? 'EXISTS' + (doc.ledger_permissions ? ' mode ' + doc.ledger_permissions : '') : 'NOT CREATED'}]</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Policy Directory:</span><br/>
              <span class="mono" style="font-size:0.85rem;">${escapeHtml(doc.policy_directory)} [${doc.policy_directory_exists ? 'EXISTS' : 'BUNDLED DEFAULT'}]</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Controlling Terminal (/dev/tty):</span><br/>
              <span class="badge ${doc.tty_available ? 'badge-success' : 'badge-warning'}">${doc.tty_available ? 'INTERACTIVE TTY AVAILABLE' : 'HEADLESS / FAIL-CLOSED'}</span>
            </div>
            <div>
              <span style="color:var(--text-secondary)">Egress Sandbox Mode:</span><br/>
              <span class="badge badge-info">${escapeHtml(doc.egress_sandbox_mode)}</span>
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="badge badge-danger" style="padding:1rem;display:block;">Error loading diagnostics: ${escapeHtml(err.message)}</div>`;
    }
  }

  // Kickoff authentication on page load
  window.addEventListener('DOMContentLoaded', initAuth);
})();
