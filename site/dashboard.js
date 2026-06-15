const demoScans = [
  { repo: 'example-agent-app', risk: 82, critical: 4, high: 6, medium: 12, low: 5, status: 'Needs review' },
  { repo: 'mcp-network-tools', risk: 64, critical: 1, high: 4, medium: 9, low: 8, status: 'Review' },
  { repo: 'claude-skill-pack', risk: 38, critical: 0, high: 2, medium: 5, low: 11, status: 'Healthy' },
  { repo: 'internal-coding-agent', risk: 91, critical: 6, high: 8, medium: 14, low: 3, status: 'Critical' }
];

const state = {
  scans: demoScans,
  report: null,
  findings: [],
  categories: {},
  severities: { critical: 0, high: 0, medium: 0, low: 0 }
};

function init() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('reportFile');

  document.getElementById('seedDemo').addEventListener('click', () => {
    state.report = null;
    state.findings = [];
    state.categories = {};
    state.severities = { critical: 0, high: 0, medium: 0, low: 0 };
    state.scans = demoScans;
    document.getElementById('reportStatus').textContent = 'No report loaded. Demo data is active.';
    renderAll();
  });

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', event => {
    event.preventDefault();
    dropZone.classList.add('drag');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
  dropZone.addEventListener('drop', event => {
    event.preventDefault();
    dropZone.classList.remove('drag');
    const file = event.dataTransfer.files[0];
    if (file) loadReport(file);
  });
  fileInput.addEventListener('change', event => {
    const file = event.target.files[0];
    if (file) loadReport(file);
  });

  renderAll();
}

function loadReport(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const report = JSON.parse(reader.result);
      state.report = report;
      state.scans = buildScansFromReport(report);
      state.findings = normalizeFindings(report.findings || []);
      state.categories = countBy(state.findings, 'category');
      state.severities = countBy(state.findings, 'severity');
      document.getElementById('reportStatus').textContent = `Loaded ${file.name} from ${report.finished_at || 'unknown time'}.`;
      renderAll();
    } catch (error) {
      document.getElementById('reportStatus').textContent = `Could not parse JSON: ${error.message}`;
    }
  };
  reader.readAsText(file);
}

function buildScansFromReport(report) {
  const summary = report.summary || {};
  const counts = summary.counts_by_severity || {};
  const risk = summary.risk_score ?? 0;
  return [
    {
      repo: report.target || 'agentsec-report.json',
      risk,
      critical: counts.critical || 0,
      high: counts.high || 0,
      medium: counts.medium || 0,
      low: counts.low || 0,
      status: risk > 75 ? 'Critical' : risk > 50 ? 'Review' : 'Healthy'
    }
  ];
}

function normalizeFindings(findings) {
  return findings.map(finding => ({
    severity: finding.severity || 'low',
    rule_id: finding.rule_id || 'unknown-rule',
    title: finding.title || finding.rule_id || 'Finding',
    message: finding.message || '',
    category: finding.category || 'uncategorized',
    file: finding.file || 'unknown',
    line: finding.line || 1,
    snippet: finding.snippet || '',
    evidence: finding.evidence || ''
  }));
}

function renderAll() {
  const risk = Math.round(state.scans.reduce((sum, scan) => sum + scan.risk, 0) / Math.max(state.scans.length, 1));
  const filesScanned = state.report ? state.report.files_scanned || 0 : state.scans.length;
  const critical = state.severities.critical || state.scans.reduce((sum, scan) => sum + scan.critical, 0);
  const findings = state.findings.length || state.scans.reduce((sum, scan) => sum + scan.critical + scan.high + scan.medium + scan.low, 0);

  document.getElementById('riskScore').textContent = risk;
  document.getElementById('riskMeter').style.width = `${risk}%`;
  document.getElementById('filesScanned').textContent = filesScanned;
  document.getElementById('findingCount').textContent = findings;
  document.getElementById('criticalCount').textContent = critical;
  document.getElementById('mrr').textContent = '$499';

  renderScanTable();
  renderFindings();
  drawRiskChart();
  drawCategoryChart();
}

function renderScanTable() {
  const table = document.getElementById('scanTable');
  table.innerHTML = '<div class="row header"><span>Repository</span><span>Risk</span><span>Critical</span><span>High</span><span>Status</span></div>' + state.scans.map(scan => `
    <div class="row">
      <strong>${escapeHtml(scan.repo)}</strong>
      <span><span class="badge ${riskClass(scan.risk)}">${scan.risk}</span></span>
      <span>${scan.critical}</span>
      <span>${scan.high}</span>
      <span>${escapeHtml(scan.status)}</span>
    </div>
  `).join('');
}

function renderFindings() {
  const list = document.getElementById('findingList');
  if (!state.findings.length) {
    list.innerHTML = '<p class="report-status">No file-level findings loaded.</p>';
    return;
  }
  list.innerHTML = state.findings.map((finding, index) => `
    <article class="finding-card">
      <header>
        <div>
          <h3>${escapeHtml(finding.title)}</h3>
          <div class="finding-meta">${escapeHtml(finding.category)} · ${escapeHtml(finding.file)}:${finding.line}</div>
        </div>
        <span class="badge ${finding.severity}">${escapeHtml(finding.severity)}</span>
      </header>
      <label><input type="checkbox" data-finding-index="${index}">Review status</label>
      <code>${escapeHtml(finding.snippet || finding.evidence || finding.message)}</code>
    </article>
  `).join('');
}

function drawRiskChart() {
  const canvas = document.getElementById('riskChart');
  const ctx = canvas.getContext('2d');
  clearCanvas(canvas, ctx);
  const pad = 48;
  const width = canvas.width;
  const height = canvas.height;
  ctx.strokeStyle = 'rgba(0,255,136,.28)';
  ctx.lineWidth = 2;
  for (let i = 0; i <= 4; i += 1) {
    const y = pad + i * ((height - pad * 2) / 4);
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(width - pad, y);
    ctx.stroke();
  }
  const step = (width - pad * 2) / Math.max(state.scans.length - 1, 1);
  ctx.lineWidth = 4;
  ctx.strokeStyle = '#00ff88';
  ctx.beginPath();
  state.scans.forEach((scan, index) => {
    const x = pad + index * step;
    const y = height - pad - scan.risk * ((height - pad * 2) / 100);
    if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
  state.scans.forEach((scan, index) => {
    const x = pad + index * step;
    const y = height - pad - scan.risk * ((height - pad * 2) / 100);
    ctx.fillStyle = scan.risk > 75 ? '#ff5c7a' : scan.risk > 50 ? '#ffd166' : '#00ff88';
    ctx.beginPath();
    ctx.arc(x, y, 7, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#9aa8bd';
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(shortName(scan.repo), x, height - 16);
  });
}

function drawCategoryChart() {
  const canvas = document.getElementById('categoryChart');
  const ctx = canvas.getContext('2d');
  clearCanvas(canvas, ctx);
  const entries = Object.entries(state.categories).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    ctx.fillStyle = '#9aa8bd';
    ctx.font = '14px Inter, sans-serif';
    ctx.fillText('No category data loaded', 32, 48);
    return;
  }
  const max = Math.max(...entries.map(([, count]) => count), 1);
  const pad = 42;
  const barHeight = Math.max(18, (canvas.height - pad * 2) / entries.length - 10);
  entries.forEach(([category, count], index) => {
    const y = pad + index * (barHeight + 18);
    const width = ((canvas.width - pad * 2) * count) / max;
    ctx.fillStyle = index % 2 ? '#bd93f9' : '#00ff88';
    roundRect(ctx, pad, y, width, barHeight, 10);
    ctx.fill();
    ctx.fillStyle = '#f4f7fb';
    ctx.font = '13px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(category, 12, y + barHeight / 2 + 5);
    ctx.textAlign = 'right';
    ctx.fillText(String(count), canvas.width - 12, y + barHeight / 2 + 5);
  });
}

function clearCanvas(canvas, ctx) {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = 'rgba(7, 12, 22, 0.42)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
}

function roundRect(ctx, x, y, width, height, radius) {
  const r = Math.min(radius, width / 2, height / 2);
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + width, y, x + width, y + height, r);
  ctx.arcTo(x + width, y + height, x, y + height, r);
  ctx.arcTo(x, y + height, x, y, r);
  ctx.arcTo(x, y, x + width, y, r);
  ctx.closePath();
}

function countBy(items, key) {
  return items.reduce((counts, item) => {
    const value = item[key] || 'unknown';
    counts[value] = (counts[value] || 0) + 1;
    return counts;
  }, {});
}

function riskClass(risk) {
  return risk > 75 ? 'critical' : risk > 50 ? 'high' : 'low';
}

function shortName(name) {
  return name.length > 22 ? `${name.slice(0, 19)}...` : name;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));
}

init();
