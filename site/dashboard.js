const scans = [
  { repo: 'example-agent-app', risk: 82, critical: 4, high: 6, medium: 12, low: 5, status: 'Needs review' },
  { repo: 'mcp-network-tools', risk: 64, critical: 1, high: 4, medium: 9, low: 8, status: 'Review' },
  { repo: 'claude-skill-pack', risk: 38, critical: 0, high: 2, medium: 5, low: 11, status: 'Healthy' },
  { repo: 'internal-coding-agent', risk: 91, critical: 6, high: 8, medium: 14, low: 3, status: 'Critical' }
];

function render() {
  const risk = Math.round(scans.reduce((sum, scan) => sum + scan.risk, 0) / scans.length);
  document.getElementById('riskScore').textContent = risk;
  document.getElementById('repoCount').textContent = scans.length;
  document.getElementById('criticalCount').textContent = scans.reduce((sum, scan) => sum + scan.critical, 0);
  document.getElementById('auditCount').textContent = 7;
  document.getElementById('mrr').textContent = '$499';

  const table = document.getElementById('scanTable');
  table.innerHTML = '<div class="row header"><span>Repository</span><span>Risk</span><span>Critical</span><span>High</span><span>Status</span></div>' + scans.map(scan => `
    <div class="row">
      <strong>${scan.repo}</strong>
      <span><span class="badge ${scan.risk > 75 ? 'critical' : scan.risk > 50 ? 'high' : ''}">${scan.risk}</span></span>
      <span>${scan.critical}</span>
      <span>${scan.high}</span>
      <span>${scan.status}</span>
    </div>
  `).join('');

  const canvas = document.getElementById('riskChart');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = '#24d6a8';
  ctx.lineWidth = 4;
  ctx.beginPath();
  scans.forEach((scan, index) => {
    const x = 80 + index * 190;
    const y = 220 - scan.risk * 1.8;
    if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
  scans.forEach((scan, index) => {
    const x = 80 + index * 190;
    const y = 220 - scan.risk * 1.8;
    ctx.fillStyle = scan.risk > 75 ? '#ff5c7a' : '#24d6a8';
    ctx.beginPath();
    ctx.arc(x, y, 7, 0, Math.PI * 2);
    ctx.fill();
  });
}

document.getElementById('seedDemo').addEventListener('click', render);
render();
