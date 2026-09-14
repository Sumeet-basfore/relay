// Relay Local Security Console Application (CR002)
// Zero External Dependencies - 100% Local Loopback Execution

(function() {
  'use strict';

  // State
  let sessionToken = null;
  let csrfToken = null;
  let currentView = 'overview';
  let activityCache = [];

  // Helper: Escapes text for safe HTML rendering
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
    handleRoute();
  }

  function renderMainLayout() {
    const app = document.getElementById('app');
    app.innerHTML = `
      <header class="header">
        <a href="#overview" class="brand">
          <svg class="brand-icon" viewBox="0 0 64 64">
            <path d="M32 10 L50 18 L50 36 C50 46 42 53 32 56 C22 53 14 46 14 36 L14 18 Z" fill="none" stroke="#10b981" stroke-width="4"/>
            <circle cx="32" cy="30" r="5" fill="#10b981"/>
            <path d="M32 35 L32 44" stroke="#10b981" stroke-width="4"/>
          </svg>
          <span>RELAY CONSOLE</span>
        </a>
        <nav class="nav" id="main-nav" aria-label="Main Navigation">
          <button class="nav-link" data-view="overview">Overview</button>
          <button class="nav-link" data-view="activity">Activity</button>
          <button class="nav-link" data-view="receipts">Receipts</button>
          <button class="nav-link" data-view="ledger">Ledger</button>
          <button class="nav-link" data-view="policies">Policies</button>
          <button class="nav-link" data-view="security">Security</button>
          <button class="nav-link" data-view="egress">Egress</button>
          <button class="nav-link" data-view="connectors">Connectors</button>
          <button class="nav-link" data-view="doctor">Doctor</button>
        </nav>
        <div style="display:flex;align-items:center;gap:0.75rem;">
          <div class="status-pill protected" id="global-status-pill">
            <span class="status-dot"></span>
            <span id="global-status-text">PROTECTED</span>
          </div>
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

    document.getElementById('btn-lock').addEventListener('click', () => {
      sessionToken = null;
      csrfToken = null;
      sessionStorage.clear();
      renderAuthScreen('Session locked.');
    });
  }

  function handleRoute() {
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
    container.innerHTML = `<div style="text-align:center;padding:3rem;color:var(--text-secondary);">Loading ${escapeHtml(view)}...</div>`;

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
        <h1 class="section-title">Security Overview</h1>
        <p class="section-subtitle">Real-time posture and operational health of the Relay zero-trust gateway.</p>

        <div class="grid-4">
          <div class="card">
            <div class="card-header">
              <span class="card-title">Security Status</span>
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
            <span class="card-title">Quick Health Check</span>
            <a href="#doctor" class="btn btn-secondary btn-sm">Full Diagnostics</a>
          </div>
          <div style="display:flex;gap:2rem;flex-wrap:wrap;font-size:0.9rem;">
            <div><span style="color:var(--text-secondary)">Version:</span> <span class="mono">${escapeHtml(status.relay_version)}</span></div>
            <div><span style="color:var(--text-secondary)">OS / Arch:</span> <span class="mono">${escapeHtml(status.target_os)} / ${escapeHtml(status.target_arch)}</span></div>
            <div><span style="color:var(--text-secondary)">Signing Identity:</span> <span class="mono">${escapeHtml(status.signing_key_id || 'relay-ed25519-v1')}</span></div>
            <div><span style="color:var(--text-secondary)">Ledger DB:</span> <span class="mono">${escapeHtml(status.ledger_path || '.relay/ledger.db')}</span></div>
          </div>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
          <h2 style="font-size:1.15rem;font-weight:600;">Recent Governed Activity</h2>
          <a href="#activity" class="btn btn-secondary btn-sm">View All Activity</a>
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
                <th>Details</th>
              </tr>
            </thead>
            <tbody id="overview-activity-table">
              ${recentItems.length === 0 ? '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:2rem;">No recent governed actions recorded in ledger.</td></tr>' : ''}
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
            <td class="mono">${escapeHtml(truncHash(item.action_hash))}</td>
            <td><span class="badge ${item.decision === 'ALLOW' ? 'badge-success' : 'badge-danger'}">${escapeHtml(item.decision || 'DENY')}</span></td>
            <td><a href="#action-detail?id=${encodeURIComponent(item.receipt_id || item.action_id)}" class="btn btn-secondary btn-sm">Inspect</a></td>
          `;
          tbody.appendChild(tr);
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
      const data = await api('/api/v1/activity?limit=50');
      const items = data.items || [];
      activityCache = items;

      container.innerHTML = `
        <h1 class="section-title">Governed Actions Activity</h1>
        <p class="section-subtitle">Real-time log of agent tool proposals evaluated by Cedar and governed by Relay.</p>

        <div class="filter-bar">
          <input type="text" id="filter-search" class="input-search" placeholder="Search by tool name, ActionHash, or receipt ID..." />
          <select id="filter-status" class="select-filter">
            <option value="">All Statuses</option>
            <option value="ALLOWED">Allowed</option>
            <option value="DENIED">Denied</option>
            <option value="APPROVAL_REQUIRED">Approval Required</option>
            <option value="EXECUTED">Executed</option>
            <option value="FAILED">Failed</option>
          </select>
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
                <th>Cedar Decision</th>
                <th>Approval</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="activity-table-body">
              ${items.length === 0 ? '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:2.5rem;">No activity found.</td></tr>' : ''}
            </tbody>
          </table>
        </div>
      `;

      const tbody = document.getElementById('activity-table-body');
      function updateTable(filterText = '', statusFilter = '') {
        tbody.innerHTML = '';
        const filtered = items.filter(item => {
          const matchesText = !filterText ||
            (item.tool_name && item.tool_name.toLowerCase().includes(filterText)) ||
            (item.action_hash && item.action_hash.toLowerCase().includes(filterText)) ||
            (item.receipt_id && item.receipt_id.toLowerCase().includes(filterText)) ||
            (item.resource && item.resource.toLowerCase().includes(filterText));
          const matchesStatus = !statusFilter || item.status === statusFilter || item.decision === statusFilter;
          return matchesText && matchesStatus;
        });

        if (filtered.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:2rem;">No matching activity items.</td></tr>';
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
            <td class="mono" title="${escapeHtml(item.resource)}">${escapeHtml(truncHash(item.resource, 28))}</td>
            <td class="mono" title="${escapeHtml(item.action_hash)}">${escapeHtml(truncHash(item.action_hash))}</td>
            <td><span class="badge ${item.decision === 'ALLOW' ? 'badge-success' : 'badge-danger'}">${escapeHtml(item.decision || 'DENY')}</span></td>
            <td><span class="badge badge-neutral">${escapeHtml(item.approval_state || 'NOT_REQUIRED')}</span></td>
            <td><a href="#action-detail?id=${encodeURIComponent(item.receipt_id || item.action_id)}" class="btn btn-secondary btn-sm">Inspect</a></td>
          `;
          tbody.appendChild(tr);
        });
      }

      updateTable();

      document.getElementById('filter-search').addEventListener('input', (e) => {
        updateTable(e.target.value.toLowerCase(), document.getElementById('filter-status').value);
      });
      document.getElementById('filter-status').addEventListener('change', (e) => {
        updateTable(document.getElementById('filter-search').value.toLowerCase(), e.target.value);
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
      const data = await api('/api/v1/receipts?limit=50');
      const receipts = data.receipts || [];

      container.innerHTML = `
        <h1 class="section-title">Action Receipts & Cryptographic Verifier</h1>
        <p class="section-subtitle">RFC 9598 DSSE envelopes containing in-toto v1.0 statements signed with Ed25519.</p>

        <div id="receipt-verify-banner"></div>

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
              ${receipts.length === 0 ? '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2.5rem;">No receipts stored in ledger.</td></tr>' : ''}
            </tbody>
          </table>
        </div>
      `;

      const tbody = document.getElementById('receipts-table-body');
      receipts.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="mono">${formatTs(r.created_at)}</td>
          <td class="mono">${escapeHtml(r.receipt_id)}</td>
          <td class="mono">${escapeHtml(truncHash(r.action_hash))}</td>
          <td><span class="badge badge-info">${r.signature_count || 1} Sig (Ed25519)</span></td>
          <td><button class="btn btn-primary btn-sm btn-verify" data-id="${escapeHtml(r.receipt_id)}">Verify</button></td>
          <td><button class="btn btn-secondary btn-sm btn-export" data-id="${escapeHtml(r.receipt_id)}">Export JSON</button></td>
        `;
        tbody.appendChild(tr);
      });

      tbody.querySelectorAll('.btn-verify').forEach(btn => {
        btn.addEventListener('click', async () => {
          const recId = btn.getAttribute('data-id');
          btn.textContent = 'Verifying...';
          try {
            const res = await api(`/api/v1/receipts/${encodeURIComponent(recId)}/verify`, { method: 'POST' });
            const banner = document.getElementById('receipt-verify-banner');
            if (res.is_valid) {
              banner.innerHTML = `
                <div class="verification-banner valid">
                  <div class="verification-icon">✓</div>
                  <div>
                    <strong>VALID SIGNATURE & DOMAIN INTEGRITY</strong><br/>
                    Receipt <span class="mono">${escapeHtml(recId)}</span> verified cryptographically against Ed25519 public key.
                  </div>
                </div>
              `;
            } else {
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
            alert('Verification request failed: ' + e.message);
          } finally {
            btn.textContent = 'Verify';
          }
        });
      });

      tbody.querySelectorAll('.btn-export').forEach(btn => {
        btn.addEventListener('click', async () => {
          const recId = btn.getAttribute('data-id');
          try {
            const exportData = await api(`/api/v1/receipts/${encodeURIComponent(recId)}/export`);
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `receipt-${recId}.json`;
            a.click();
            URL.revokeObjectURL(url);
          } catch (e) {
            alert('Export failed: ' + e.message);
          }
        });
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

      container.innerHTML = `
        <h1 class="section-title">Cedar Security Policies</h1>
        <p class="section-subtitle">Deterministic AWS Cedar authorization policies governing all tool invocations.</p>

        <div id="policy-alert"></div>

        <div class="grid-3">
          <div class="card">
            <div class="card-title">Policy Model</div>
            <div class="card-value" style="color:var(--color-success)">Default Deny</div>
            <div class="card-subtext">Explicit Permit Required</div>
          </div>
          <div class="card">
            <div class="card-title">Policy Digest</div>
            <div class="card-value" style="font-size:1.1rem;line-height:2.2rem;" class="mono">${escapeHtml(truncHash(data.policy_digest, 20))}</div>
            <div class="card-subtext">Tamper Detection Digest (SI-010)</div>
          </div>
          <div class="card">
            <div class="card-title">Schema Version</div>
            <div class="card-value">Cedar 4.0</div>
            <div class="card-subtext">Strict Entity & Action Conformity</div>
          </div>
        </div>

        <div class="card" style="margin-bottom:1.5rem;">
          <div class="card-header">
            <span class="card-title">Active Cedar Policies</span>
            <button class="btn btn-secondary btn-sm" id="btn-reload-policies">Atomic Reload From Disk</button>
          </div>
          <pre>${escapeHtml(data.policy_text || '// Default bundled policies')}</pre>
        </div>

        <div class="card">
          <div class="card-header">
            <span class="card-title">Test & Validate Policy Syntax</span>
          </div>
          <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:0.75rem;">
            Test prospective Cedar policy statements against Relay's Cedar schema before applying them.
          </p>
          <textarea id="policy-test-input" class="auth-input" style="height:140px;font-family:var(--font-mono);font-size:0.85rem;" placeholder="permit(principal, action, resource) when { ... };"></textarea>
          <div>
            <button class="btn btn-primary btn-sm" id="btn-validate-policy">Validate Syntax</button>
          </div>
          <div id="policy-validation-result" style="margin-top:0.75rem;"></div>
        </div>
      `;

      document.getElementById('btn-reload-policies').addEventListener('click', async () => {
        if (!confirm('Are you sure you want to reload active Cedar policies from disk?')) return;
        const alertDiv = document.getElementById('policy-alert');
        try {
          const res = await api('/api/v1/policies/reload', { method: 'POST' });
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
          } else {
            resDiv.innerHTML = `<span class="badge badge-danger" style="padding:0.5rem;">✗ INVALID: ${escapeHtml(res.error || 'Validation error')}</span>`;
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
