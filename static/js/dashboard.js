/*
   dashboard.js
   Author: Gokul (copied for integration)
   Purpose: Javascript logic
*/

/* SECURETRIAGE SOC TERMINAL — Author: Gokul */

let severityChart = null;
let ipChart = null;
let allAlertsData = [];
let uptimeSeconds = 0;
let radarAngle = 0;

const BOOT_MESSAGES = [
  "[ OK ] Loading kernel modules...",
  "[ OK ] Mounting encrypted volumes...",
  "[ OK ] Initialising network interfaces...",
  "[ OK ] Starting log ingestion engine...",
  "[ OK ] Connecting to SQLite datastore...",
  "[ OK ] Loading triage rule engine v2.4...",
  "[ OK ] Parsing threat intelligence feeds...",
  "[ OK ] Activating IP blacklist module...",
  "[ OK ] Starting Flask API server on :5001...",
  "[ OK ] All systems nominal. Dashboard ready.",
];

function initMatrix() {
  const canvas = document.getElementById('matrix-canvas');
  const ctx = canvas.getContext('2d');
  canvas.width  = window.innerWidth;
  canvas.height = window.innerHeight;

  const cols = Math.floor(canvas.width / 16);
  const drops = Array(cols).fill(1);
  const chars  = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ'.split('');

  function draw() {
    ctx.fillStyle = 'rgba(0,0,0,0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#00ff41';
    ctx.font = '12px Share Tech Mono';

    drops.forEach((y, i) => {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * 16, y * 16);
      if (y * 16 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }

  setInterval(draw, 50);
  window.addEventListener('resize', () => {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  });
}

function runBootSequence() {
  const logEl  = document.getElementById('boot-log');
  const fillEl = document.getElementById('boot-fill');
  const pctEl  = document.getElementById('boot-pct');
  let pct = 0;
  let i   = 0;

  const interval = setInterval(() => {
    if (i < BOOT_MESSAGES.length) {
      const line = document.createElement('div');
      line.className = 'boot-log-line';
      line.textContent = BOOT_MESSAGES[i];
      line.style.color = BOOT_MESSAGES[i].includes('OK') ? 'rgba(0,255,65,0.7)' : 'rgba(255,42,42,0.7)';
      logEl.appendChild(line);
      logEl.scrollTop = logEl.scrollHeight;
      i++;
    }

    pct = Math.min(100, pct + (100 / BOOT_MESSAGES.length));
    fillEl.style.width = pct + '%';
    pctEl.textContent  = Math.round(pct) + '%';

    if (pct >= 100) {
      clearInterval(interval);
      setTimeout(() => {
        document.getElementById('loader').classList.add('out');
        animateCards();
        refreshDashboard();
      }, 600);
    }
  }, 120);
}

function initRadar() {
  const canvas = document.getElementById('radar-canvas');
  const ctx    = canvas.getContext('2d');
  const cx = 20, cy = 20, r = 16;

  function drawRadar() {
    ctx.clearRect(0, 0, 40, 40);

    ctx.strokeStyle = 'rgba(0,255,65,0.15)';
    ctx.lineWidth = 0.5;
    [6, 11, 16].forEach(radius => {
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();
    });

    ctx.beginPath();
    ctx.moveTo(cx - r, cy); ctx.lineTo(cx + r, cy);
    ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy + r);
    ctx.stroke();

    const grad = ctx.createConicalGradient
      ? ctx.createConicalGradient(cx, cy, radarAngle)
      : null;

    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(radarAngle);

    const sweepGrad = ctx.createLinearGradient(0, 0, r, 0);
    sweepGrad.addColorStop(0, 'rgba(0,255,65,0.8)');
    sweepGrad.addColorStop(1, 'rgba(0,255,65,0)');

    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, r, -0.4, 0);
    ctx.fillStyle = sweepGrad;
    ctx.fill();
    ctx.restore();

    radarAngle += 0.04;
    requestAnimationFrame(drawRadar);
  }
  drawRadar();
}

function startUptime() {
  setInterval(() => {
    uptimeSeconds++;
    const h = String(Math.floor(uptimeSeconds / 3600)).padStart(2, '0');
    const m = String(Math.floor((uptimeSeconds % 3600) / 60)).padStart(2, '0');
    const s = String(uptimeSeconds % 60).padStart(2, '0');
    document.getElementById('uptime').textContent = `${h}:${m}:${s}`;
  }, 1000);
}

function startClock() {
  const el = document.getElementById('ftr-time');
  setInterval(() => {
    el.textContent = new Date().toLocaleString();
  }, 1000);
}

function animateCards() {
  document.querySelectorAll('.metric-card').forEach((card, i) => {
    setTimeout(() => {
      card.classList.add('loaded');
      card.querySelector('.mc-bar-fill').style.width = '60%';
    }, i * 100);
  });
}

function showStatus(msg, isError = false) {
  const bar  = document.getElementById('status-bar');
  const msgEl = document.getElementById('status-message');
  const dot   = bar.querySelector('.status-blink');
  const c = isError ? '#ff2a2a' : '#00d4ff';
  bar.classList.remove('hidden');
  bar.style.borderLeftColor = c;
  dot.style.background      = c;
  dot.style.boxShadow       = `0 0 6px ${c}`;
  msgEl.textContent          = msg;
  msgEl.style.color          = c;
}

function hideStatus() {
  document.getElementById('status-bar').classList.add('hidden');
}

function updateTimestamp() {
  document.getElementById('last-updated').textContent =
    new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function animateCount(el, target) {
  const start = parseInt(el.textContent) || 0;
  const diff  = target - start;
  const dur   = 800;
  const t0    = performance.now();
  function step(now) {
    const p = Math.min((now - t0) / dur, 1);
    const e = 1 - Math.pow(1 - p, 4);
    el.textContent = Math.round(start + diff * e);
    if (p < 1) requestAnimationFrame(step);
    else el.textContent = target;
  }
  requestAnimationFrame(step);
}

function updateTicker(msg) {
  const el = document.getElementById('ticker-content');
  el.textContent = msg + ' ◆ SYSTEM ACTIVE ◆ ' + new Date().toLocaleTimeString() + ' ◆ ';
}

function updateCards(counts, total) {
  animateCount(document.getElementById('total-count'),    total || 0);
  animateCount(document.getElementById('critical-count'), counts['CRITICAL'] || 0);
  animateCount(document.getElementById('high-count'),     counts['HIGH']     || 0);
  animateCount(document.getElementById('medium-count'),   counts['MEDIUM']   || 0);
  animateCount(document.getElementById('low-count'),      counts['LOW']      || 0);
}

const CHART_OPTS = {
  plugins: {
    tooltip: {
      backgroundColor: '#08111a',
      borderColor: '#0f2333',
      borderWidth: 1,
      titleColor: '#00ff41',
      bodyColor:  '#b0c8d8',
      titleFont:  { family: "'Share Tech Mono', monospace", size: 11 },
      bodyFont:   { family: "'Share Tech Mono', monospace" },
      padding: 10,
    }
  }
};

function updateSeverityChart(counts) {
  const ctx    = document.getElementById('severity-chart').getContext('2d');
  const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const data   = labels.map(l => counts[l] || 0);
  const colors = ['#ff2a2a', '#ff8c00', '#ffd700', '#00ff41'];

  if (severityChart) severityChart.destroy();

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.map(c => c + '22'),
        borderColor: colors,
        borderWidth: 2,
        hoverBackgroundColor: colors.map(c => c + '44'),
        hoverBorderWidth: 3,
      }]
    },
    options: {
      ...CHART_OPTS,
      cutout: '68%',
      responsive: true,
      maintainAspectRatio: true,
      animation: { duration: 1000, animateRotate: true },
      plugins: {
        ...CHART_OPTS.plugins,
        legend: {
          position: 'bottom',
          labels: {
            color: '#2a4555',
            padding: 14,
            font: { family: "'Share Tech Mono', monospace", size: 10 },
            usePointStyle: true,
          }
        }
      }
    }
  });
}

function updateIPChart(topIPs) {
  const ctx    = document.getElementById('ip-chart').getContext('2d');
  const labels = topIPs.map(i => i.source_ip);
  const data   = topIPs.map(i => i.count);
  const max    = Math.max(...data, 1);
  const colors = data.map(v => {
    const r = v / max;
    if (r > 0.8) return '#ff2a2a';
    if (r > 0.5) return '#ff8c00';
    return '#00d4ff';
  });

  if (ipChart) ipChart.destroy();

  ipChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.map(c => c + '33'),
        borderColor: colors,
        borderWidth: 1,
        borderRadius: 3,
        borderSkipped: false,
      }]
    },
    options: {
      ...CHART_OPTS,
      responsive: true,
      maintainAspectRatio: true,
      animation: { duration: 1000 },
      plugins: {
        ...CHART_OPTS.plugins,
        legend: { display: false }
      },
      scales: {
        x: {
          ticks: { color: '#2a4555', font: { family: "'Share Tech Mono', monospace", size: 9 }, maxRotation: 30 },
          grid:  { color: 'rgba(15,35,51,0.8)' },
        },
        y: {
          ticks: { color: '#2a4555', font: { family: "'Share Tech Mono', monospace", size: 9 } },
          grid:  { color: 'rgba(15,35,51,0.8)' },
          beginAtZero: true,
        }
      }
    }
  });
}

function scoreColor(s) {
  if (s >= 80) return '#ff2a2a';
  if (s >= 60) return '#ff8c00';
  if (s >= 30) return '#ffd700';
  return '#00ff41';
}

function renderAlerts(alerts) {
  const tbody = document.getElementById('alerts-body');
  tbody.innerHTML = '';

  if (!alerts.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">
      <div class="empty-state">
        <div class="empty-hex">⬡</div>
        <div class="empty-text">NO ALERTS FOUND</div>
        <div class="empty-cursor">_</div>
      </div></td></tr>`;
    return;
  }

  alerts.forEach((a, i) => {
    const tr = document.createElement('tr');
    tr.style.animationDelay = `${i * 25}ms`;
    tr.innerHTML = `
      <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
      <td class="score-val" style="color:${scoreColor(a.score)}">${a.score}</td>
      <td style="font-size:10px;letter-spacing:1px;">${a.event_type}</td>
      <td class="ip-val">${a.source_ip}</td>
      <td style="font-size:10px;color:#2a4555;">${a.timestamp}</td>
      <td style="font-size:10px;color:#2a4555;">${a.log_source}</td>
      <td class="raw-cell" title="${a.raw_log}">${a.raw_log}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderBlacklist(ips) {
  const tbody = document.getElementById('blacklist-body');
  tbody.innerHTML = '';

  if (!ips.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty-cell">
      <div class="empty-state">
        <div class="empty-hex" style="color:#00ff41">✓</div>
        <div class="empty-text">NO THREATS DETECTED — SYSTEM CLEAN</div>
      </div></td></tr>`;
    return;
  }

  ips.forEach(ip => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family:var(--mono);color:#ff2a2a;text-shadow:0 0 6px rgba(255,42,42,0.4);font-size:12px;">${ip.ip_address}</td>
      <td style="font-size:11px;">${ip.reason}</td>
      <td style="font-size:10px;color:#2a4555;font-family:var(--mono);">${ip.flagged_at}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function fetchAlerts(severity = null) {
  try {
    let url = '/api/alerts';
    if (severity && severity !== 'ALL') url += `?severity=${severity}`;
    const d = await (await fetch(url)).json();
    renderAlerts(d.alerts);
  } catch (e) { showStatus('ERROR FETCHING ALERTS: ' + e.message, true); }
}

async function fetchStats() {
  try {
    const d = await (await fetch('/api/stats')).json();
    updateCards(d.severity_counts, d.total_alerts);
    updateSeverityChart(d.severity_counts);
    updateIPChart(d.top_ips);
  } catch (e) { showStatus('ERROR FETCHING STATS: ' + e.message, true); }
}

async function fetchBlacklist() {
  try {
    const d = await (await fetch('/api/blacklist')).json();
    renderBlacklist(d.blacklisted_ips);
  } catch (e) { console.error(e); }
}

async function refreshDashboard() {
  const icon = document.querySelector('#btn-refresh .cmd-prefix');
  icon.style.animation = 'spin 0.6s linear infinite';
  showStatus('REFRESHING DASHBOARD...');
  await Promise.all([fetchAlerts(), fetchStats(), fetchBlacklist()]);
  updateTimestamp();
  hideStatus();
  icon.style.animation = '';
}

document.getElementById('btn-analyse').addEventListener('click', async () => {
  const btn = document.getElementById('btn-analyse');
  btn.disabled = true;
  btn.querySelector('.cmd-text').textContent = 'PROCESSING...';
  showStatus('INGESTING AND TRIAGING LOG FILES...');
  try {
    const d = await (await fetch('/api/process', { method: 'POST' })).json();
    updateTicker(d.message.toUpperCase());
    showStatus('ANALYSIS COMPLETE — ' + d.message.toUpperCase());
    await refreshDashboard();
    setTimeout(hideStatus, 4000);
  } catch (e) {
    showStatus('CRITICAL ERROR: ' + e.message, true);
  } finally {
    btn.disabled = false;
    btn.querySelector('.cmd-text').textContent = 'RUN ANALYSIS';
  }
});

document.getElementById('btn-refresh').addEventListener('click', refreshDashboard);

document.getElementById('btn-clear').addEventListener('click', async () => {
  if (!confirm('FLUSH ALL ALERTS FROM DATABASE?\n\nThis action cannot be undone.')) return;
  try {
    await fetch('/api/clear', { method: 'POST' });
    showStatus('DATABASE FLUSHED — ALL RECORDS CLEARED');
    await refreshDashboard();
    updateTicker('DATABASE FLUSHED — ALL ALERT RECORDS CLEARED');
    setTimeout(hideStatus, 2500);
  } catch (e) { showStatus('ERROR: ' + e.message, true); }
});

document.getElementById('file-upload').addEventListener('change', e => {
  const name = e.target.files[0]?.name || 'DROP LOG FILE HERE';
  document.getElementById('file-name-disp').textContent = name;
  document.getElementById('file-label').style.borderColor = '#00d4ff';
  document.getElementById('file-label').style.color = '#00d4ff';
});

document.getElementById('btn-upload').addEventListener('click', async () => {
  const fi = document.getElementById('file-upload');
  const lt = document.getElementById('log-type-select').value;
  if (!fi.files.length) { showStatus('NO FILE SELECTED — CHOOSE A LOG FILE FIRST', true); return; }
  const fd = new FormData();
  fd.append('file', fi.files[0]);
  fd.append('log_type', lt);
  showStatus('UPLOADING AND INGESTING LOG FILE...');
  try {
    const d = await (await fetch('/api/upload', { method: 'POST', body: fd })).json();
    showStatus('INGEST COMPLETE — ' + d.message.toUpperCase());
    await refreshDashboard();
    updateTicker('FILE INGESTED: ' + fi.files[0].name.toUpperCase());
    setTimeout(hideStatus, 3000);
  } catch (e) { showStatus('UPLOAD ERROR: ' + e.message, true); }
});

document.querySelectorAll('.flt').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.flt').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    fetchAlerts(btn.getAttribute('data-severity'));
  });
});

document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'r') {
    e.preventDefault();
    document.getElementById('btn-analyse').click();
  }
});

document.addEventListener('DOMContentLoaded', () => {
  initMatrix();
  initRadar();
  runBootSequence();
  startUptime();
  startClock();
});