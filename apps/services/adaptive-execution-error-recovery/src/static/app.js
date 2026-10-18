// ── NeuroShell AEERE Dashboard — Frontend Logic ──

const API = '';

// ── Health Check ──
async function checkHealth() {
  try {
    const resp = await fetch(`${API}/health`);
    const data = await resp.json();
    setBadge('badgeDocker', data.docker);
    setBadge('badgeRedis', data.redis);
    setBadge('badgeDataset', data.dataset_corrections);
    document.getElementById('datasetCount').textContent = data.dataset_entries.toLocaleString();
    document.getElementById('modelName').textContent = data.model || '—';
    setBadge('badgeModel', true);
  } catch {
    ['badgeDocker','badgeRedis','badgeDataset','badgeModel'].forEach(id => setBadge(id, false));
  }
}

function setBadge(id, ok) {
  const el = document.getElementById(id);
  el.classList.remove('ok','warn','err');
  el.classList.add(ok ? 'ok' : 'err');
}

// ── Generate Session ID ──
function genSessionId() {
  return 'sess-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2,6);
}

// ── Auto-detect tool from command ──
function autoDetectTool(cmd) {
  const parts = cmd.trim().split(/\s+/);
  if (!parts.length) return '';
  let tool = parts[0];
  if (tool === 'sudo' && parts.length > 1) tool = parts[1];
  if (cmd.includes('&&')) {
    const after = cmd.split('&&').pop().trim().split(/\s+/);
    if (after.length) tool = after[0];
  }
  return tool;
}

// ── Command Input Listeners ──
document.getElementById('commandInput').addEventListener('input', (e) => {
  const tool = autoDetectTool(e.target.value);
  if (tool) document.getElementById('toolInput').value = tool;
});

document.getElementById('commandInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    executeCommand();
  }
});

// ── Execute Command ──
async function executeCommand() {
  const btn = document.getElementById('btnExecute');
  const cmdInput = document.getElementById('commandInput');
  const command = cmdInput.value.trim();

  if (!command) { cmdInput.focus(); return; }

  const sessionId = document.getElementById('sessionInput').value.trim() || genSessionId();
  document.getElementById('sessionInput').value = sessionId;

  // Lock UI
  btn.classList.add('loading');
  btn.disabled = true;

  // Reset results
  hideResults();

  const payload = {
    command: command,
    tool: document.getElementById('toolInput').value.trim() || autoDetectTool(command) || 'unknown',
    session_id: sessionId,
    intent_ref: document.getElementById('intentInput').value.trim() || 'NETWORK_SCAN',
    estimated_duration: document.getElementById('durationInput').value,
  };

  try {
    const resp = await fetch(`${API}/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    renderResults(data);
  } catch (err) {
    showBanner('failed', `❌ Request failed: ${err.message}`);
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

// ── Hide All Results ──
function hideResults() {
  document.getElementById('emptyState').classList.add('hidden');
  document.getElementById('statusBanner').classList.remove('visible','success','recovered','failed');
  document.getElementById('resultSummary').classList.add('hidden');
  document.getElementById('correctionTimeline').classList.add('hidden');
  document.getElementById('stdoutPanel').classList.add('hidden');
  document.getElementById('stderrPanel').classList.add('hidden');
  document.getElementById('failureReport').classList.add('hidden');
}

// ── Show Status Banner ──
function showBanner(type, message) {
  const banner = document.getElementById('statusBanner');
  banner.className = 'status-banner visible ' + type;
  banner.innerHTML = message;
}

// ── Render Results ──
function renderResults(data) {
  // Status banner
  const icons = { success: '✅', recovered: '🔄', failed: '❌' };
  const msgs = {
    success: `Command executed successfully on first attempt`,
    recovered: `Command recovered after ${data.recovery_log.length} correction(s)`,
    failed: `Command failed after ${(data.recovery_log?.length || 0) + 1} attempt(s)`,
  };
  showBanner(data.status, `${icons[data.status] || '❓'} ${msgs[data.status] || data.status}`);

  // Summary stats
  const summaryEl = document.getElementById('resultSummary');
  summaryEl.classList.remove('hidden');
  document.getElementById('summarySubtitle').textContent = `Session: ${data.session_id}`;

  const statStatus = document.getElementById('statStatus');
  statStatus.textContent = data.status.toUpperCase();
  statStatus.className = 'stat-value ' + (data.status === 'success' ? 'green' : data.status === 'recovered' ? 'blue' : 'red');

  document.getElementById('statAttempts').textContent = (data.recovery_log?.length || 0) + 1;
  const exitEl = document.getElementById('statExitCode');
  exitEl.textContent = data.exit_code;
  exitEl.className = 'stat-value ' + (data.exit_code === 0 ? 'green' : 'red');
  document.getElementById('statLatency').textContent = (data.latency_ms / 1000).toFixed(1) + 's';

  // Correction timeline
  if (data.correction_history && data.correction_history.length > 0) {
    const timelineSection = document.getElementById('correctionTimeline');
    timelineSection.classList.remove('hidden');
    const container = document.getElementById('timelineContainer');
    container.innerHTML = '';

    data.correction_history.forEach((entry) => {
      const item = document.createElement('div');
      item.className = 'timeline-item';

      const dotClass = entry.approved ? 'approved' : 'blocked';
      const badgeClass = entry.approved ? 'approved' : 'blocked';
      const badgeText = entry.approved ? '✓ Approved' : '✗ Blocked';
      const sourceLabel = entry.correction_source || 'unknown';

      item.innerHTML = `
        <div class="timeline-dot ${dotClass}"></div>
        <div class="timeline-card">
          <div class="timeline-header">
            <span class="attempt-badge ${badgeClass}">Attempt ${entry.attempt} — ${badgeText}</span>
            <span class="source-tag">Source: ${sourceLabel}</span>
          </div>
          <div class="cmd-diff">
            <div class="cmd-line original">
              <span class="cmd-line-prefix">−</span>
              ${escapeHtml(entry.original_command)}
            </div>
            <div class="cmd-line corrected">
              <span class="cmd-line-prefix">+</span>
              ${escapeHtml(entry.corrected_command)}
            </div>
          </div>
          <div class="meta-row">
            <div class="meta-item">🏷️ <strong>${entry.error_class}</strong></div>
            <div class="meta-item">🔧 <strong>${entry.strategy}</strong></div>
          </div>
        </div>
      `;
      container.appendChild(item);
    });
  }

  // STDOUT
  if (data.stdout && data.stdout.trim()) {
    document.getElementById('stdoutPanel').classList.remove('hidden');
    document.getElementById('stdoutBox').textContent = data.stdout;
  }

  // STDERR
  if (data.stderr && data.stderr.trim()) {
    document.getElementById('stderrPanel').classList.remove('hidden');
    document.getElementById('stderrBox').textContent = data.stderr;
  }

  // Failure report
  if (data.failure_report && data.status === 'failed') {
    const frSection = document.getElementById('failureReport');
    frSection.classList.remove('hidden');
    const frContent = document.getElementById('failureContent');
    const fr = data.failure_report;
    frContent.innerHTML = `
      <div class="failure-item">
        <div class="label">Error Class</div>
        <div class="value">${fr.final_error_class || '—'}</div>
      </div>
      <div class="failure-item">
        <div class="label">Total Attempts</div>
        <div class="value">${fr.attempts || '—'}</div>
      </div>
      <div class="failure-item">
        <div class="label">Strategies Tried</div>
        <div class="value">${(fr.strategies_tried || []).join(', ') || '—'}</div>
      </div>
      <div class="failure-item">
        <div class="label">Recommendation</div>
        <div class="value">${fr.recommendation || '—'}</div>
      </div>
    `;
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ── Init ──
checkHealth();
setInterval(checkHealth, 15000);
