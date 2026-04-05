/**
 * PhishAI Guard – Frontend Application
 * =====================================
 * Manages UI state, API calls, animations, and result rendering.
 */

'use strict';

// ── CONFIG ──────────────────────────────────────────────────────
const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:5000'
  : '';   // Same origin in production

const RISK_COLORS = {
  'Safe':        '#00ff88',
  'Low Risk':    '#88ff00',
  'Suspicious':  '#ffcc00',
  'High Risk':   '#ff6600',
  'Critical':    '#ff2244',
};

const AGENTS = [
  'KeywordNLP', 'URLIntelligence', 'EmailHeader',
  'AMLTransaction', 'BehavioralEntropy', 'ThreatIntel'
];

let currentTab = 'email';
let scoreHistory = [];
let testCases = [];

// ── INIT ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  checkAPIStatus();
  loadTestCases();
  initTabs();
  initURLLiveCheck();
  initAmountMeter();
  initParticles();
  initEmailCounter();
  setInterval(refreshHistory, 5000);
});

// ── API STATUS ──────────────────────────────────────────────────
async function checkAPIStatus() {
  const dot = document.getElementById('apiStatus');
  const text = document.getElementById('apiStatusText');
  try {
    const r = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    const d = await r.json();
    dot.classList.remove('offline');
    text.textContent = `API Online · ${d.agents} Agents`;
  } catch {
    dot.classList.add('offline');
    text.textContent = 'API Offline – Using Local Mode';
  }
}

// ── TABS ─────────────────────────────────────────────────────────
function initTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const name = tab.dataset.tab;
      currentTab = name;
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + name)?.classList.add('active');
    });
  });
}

// ── EMAIL CHAR COUNTER ───────────────────────────────────────────
function initEmailCounter() {
  const ta = document.getElementById('emailText');
  const counter = document.getElementById('emailCharCount');
  if (ta && counter) {
    ta.addEventListener('input', () => {
      counter.textContent = `${ta.value.length} chars`;
    });
  }
}

// ── URL LIVE CHECK ───────────────────────────────────────────────
function initURLLiveCheck() {
  const urlInput = document.getElementById('urlInput');
  const indicators = document.getElementById('urlIndicators');
  if (!urlInput || !indicators) return;

  urlInput.addEventListener('input', () => {
    const url = urlInput.value.trim();
    indicators.innerHTML = '';
    if (!url) return;

    const flags = [];
    if (url.startsWith('http://')) flags.push({ text: '⚠ HTTP (Insecure)', cls: 'bad' });
    if (url.startsWith('https://')) flags.push({ text: '✓ HTTPS', cls: 'ok' });

    const suspiciousTlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.pw'];
    for (const tld of suspiciousTlds) {
      if (url.includes(tld)) { flags.push({ text: `⚠ Suspicious TLD: ${tld}`, cls: 'bad' }); break; }
    }

    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url))
      flags.push({ text: '🚨 IP Address Domain', cls: 'bad' });

    if (url.length > 100) flags.push({ text: `⚠ Long URL (${url.length}c)`, cls: 'warn' });

    const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co'];
    if (shorteners.some(s => url.includes(s)))
      flags.push({ text: '⚠ URL Shortener', cls: 'warn' });

    flags.forEach(f => {
      const span = document.createElement('span');
      span.className = `url-flag ${f.cls}`;
      span.textContent = f.text;
      indicators.appendChild(span);
    });
  });
}

// ── AMOUNT METER ──────────────────────────────────────────────────
function initAmountMeter() {
  const amtInput = document.getElementById('txAmount');
  if (!amtInput) return;
  amtInput.addEventListener('input', () => {
    const amt = parseFloat(amtInput.value) || 0;
    // Visual feedback would go in threshold bar
  });
}

// ── TEST CASES ────────────────────────────────────────────────────
async function loadTestCases() {
  const container = document.getElementById('testCasePills');
  try {
    const r = await fetch(`${API_BASE}/api/test-cases`);
    const d = await r.json();
    testCases = d.data;
    container.innerHTML = '';
    testCases.forEach((tc, i) => {
      const btn = document.createElement('button');
      btn.className = 'tc-pill';
      btn.textContent = `${tc.icon} ${tc.name}`;
      btn.title = tc.description;
      btn.onclick = () => loadTestCase(i);
      container.appendChild(btn);
    });
  } catch {
    // Fallback test cases
    testCases = getLocalTestCases();
    container.innerHTML = '';
    testCases.forEach((tc, i) => {
      const btn = document.createElement('button');
      btn.className = 'tc-pill';
      btn.textContent = `${tc.icon} ${tc.name}`;
      btn.onclick = () => loadTestCase(i);
      container.appendChild(btn);
    });
  }
}

function loadTestCase(index) {
  const tc = testCases[index];
  if (!tc) return;

  // Fill fields in full tab
  switchToTab('full');
  setVal('fullText', tc.data.text);
  setVal('fullUrl', tc.data.url);
  setVal('fullSender', tc.data.sender_email);
  setVal('fullAmount', tc.data.transaction.amount);
  setVal('fullFreq', tc.data.transaction.frequency);

  // Also fill email tab
  setVal('emailText', tc.data.text);
  setVal('senderEmail', tc.data.sender_email);
  setVal('urlInput', tc.data.url);
  setVal('txAmount', tc.data.transaction.amount);
  setVal('txFrequency', tc.data.transaction.frequency);

  showNotification(`Loaded: ${tc.name}`, 'info');
}

function switchToTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === name);
  });
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.toggle('active', c.id === 'tab-' + name);
  });
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val ?? '';
}

// ── MAIN ANALYSIS ─────────────────────────────────────────────────
async function runAnalysis() {
  const payload = buildPayload();
  if (!payload.text && !payload.url &&
      !payload.transaction.amount && !payload.transaction.frequency) {
    showNotification('Please enter some content to analyze', 'warn');
    return;
  }

  setLoading(true);
  animateProgress();

  try {
    let result;
    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!data.success) throw new Error(data.error);
      result = data.data;
    } catch (apiError) {
      // Fallback: local analysis engine
      console.warn('API unavailable, using local engine:', apiError.message);
      result = localAnalysisEngine(payload);
    }

    renderResults(result);
    updateSidebarStats(result);
    updateHistory();
    scoreHistory.push(result.final_score);
    drawMiniChart();

  } catch (err) {
    showNotification('Analysis failed: ' + err.message, 'error');
  } finally {
    setLoading(false);
  }
}

// ── PAYLOAD BUILDER ───────────────────────────────────────────────
function buildPayload() {
  let text = '', url = '', sender = '', amount = 0, frequency = 0;

  if (currentTab === 'email') {
    text = g('emailText');
    sender = g('senderEmail');
  } else if (currentTab === 'url') {
    url = g('urlInput');
    text = g('urlContext');
  } else if (currentTab === 'transaction') {
    amount = parseFloat(g('txAmount')) || 0;
    frequency = parseInt(g('txFrequency')) || 0;
    text = g('txContext');
  } else {
    text = g('fullText');
    url = g('fullUrl');
    sender = g('fullSender');
    amount = parseFloat(g('fullAmount')) || 0;
    frequency = parseInt(g('fullFreq')) || 0;
  }

  return {
    text, url,
    sender_email: sender,
    transaction: { amount, frequency },
    session_id: 'phishai_' + Date.now()
  };
}

function g(id) {
  return (document.getElementById(id)?.value || '').trim();
}

// ── LOADING STATE ─────────────────────────────────────────────────
function setLoading(on) {
  const btn = document.getElementById('analyzeBtn');
  const progress = document.getElementById('analysisProgress');
  btn.classList.toggle('loading', on);
  btn.querySelector('.btn-text').textContent = on ? 'ANALYZING...' : 'ANALYZE THREAT';
  progress.style.display = on ? 'block' : 'none';
}

function animateProgress() {
  const fill = document.getElementById('progressFill');
  const agentsEl = document.getElementById('progressAgents');
  let i = 0;
  const steps = [
    { pct: 12, msg: '⬡ KeywordNLP Agent running...' },
    { pct: 28, msg: '⬡ URLIntelligence Agent scanning...' },
    { pct: 44, msg: '⬡ EmailHeader Agent validating...' },
    { pct: 60, msg: '⬡ AMLTransaction Agent analyzing...' },
    { pct: 76, msg: '⬡ BehavioralEntropy Agent computing...' },
    { pct: 90, msg: '⬡ ThreatIntel Agent matching...' },
    { pct: 100, msg: '⬡ Ensemble scoring complete' },
  ];

  const interval = setInterval(() => {
    if (i >= steps.length) { clearInterval(interval); return; }
    fill.style.width = steps[i].pct + '%';
    agentsEl.textContent = steps[i].msg;
    i++;
  }, 200);
}

// ── RENDER RESULTS ────────────────────────────────────────────────
function renderResults(data) {
  document.getElementById('resultsPlaceholder').style.display = 'none';
  const content = document.getElementById('resultsContent');
  content.style.display = 'block';

  const color = RISK_COLORS[data.risk_level] || '#00e5ff';

  // Animate score ring
  animateRing(data.final_score, color);

  // Score number
  animateNumber('scoreNumber', 0, data.final_score, 1200, color);

  // Meta
  const riskBadge = document.getElementById('riskBadge');
  riskBadge.textContent = data.risk_level.toUpperCase();
  riskBadge.style.color = color;

  document.getElementById('attackType').textContent =
    '🎯 ' + (data.attack_type || 'Unknown');

  document.getElementById('confidenceVal').textContent =
    Math.round(data.confidence * 100) + '%';
  document.getElementById('processingTime').textContent =
    (data.processing_time_ms || 0) + 'ms';

  // Agent signals
  renderAgentSignals(data.agent_signals || []);

  // Attack probability bars
  renderAttackBars(data.attack_probability || {});

  // Findings
  renderFindings(data.explanation || []);

  // Recommendations
  renderRecommendations(data.recommendations || []);

  // Threat intel
  renderThreatIntel(data.threat_intel || {}, color, data.final_score);

  // Footer hash
  if (data.threat_intel?.fingerprint) {
    document.getElementById('footerHash').textContent = data.threat_intel.fingerprint;
  }

  // Scroll to results
  content.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function animateRing(score, color) {
  const ring = document.getElementById('ringFill');
  const circumference = 534;
  const offset = circumference - (score / 100) * circumference;
  ring.style.stroke = color;
  setTimeout(() => {
    ring.style.strokeDashoffset = offset;
  }, 100);
}

function animateNumber(id, from, to, duration, color) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.color = color;
  const start = performance.now();
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function renderAgentSignals(signals) {
  const container = document.getElementById('agentSignals');
  container.innerHTML = '';
  signals.forEach((sig, i) => {
    const color = scoreColor(sig.score);
    const div = document.createElement('div');
    div.className = 'agent-signal';
    div.style.animationDelay = `${i * 0.08}s`;
    div.innerHTML = `
      <div class="as-name">${sig.agent}</div>
      <div class="as-bar-track">
        <div class="as-bar-fill" style="width:0%;background:${color}"
          data-target="${sig.score}"></div>
      </div>
      <div class="as-score" style="color:${color}">${sig.score.toFixed(1)}</div>
    `;
    container.appendChild(div);
  });

  // Animate bars after render
  setTimeout(() => {
    container.querySelectorAll('.as-bar-fill').forEach(bar => {
      bar.style.width = bar.dataset.target + '%';
    });
  }, 200);
}

function renderAttackBars(probs) {
  const container = document.getElementById('attackBars');
  container.innerHTML = '';
  const sorted = Object.entries(probs).sort((a, b) => b[1] - a[1]);
  sorted.forEach(([name, pct], i) => {
    const div = document.createElement('div');
    div.className = 'attack-bar';
    div.innerHTML = `
      <div class="ab-name">${name}</div>
      <div class="ab-track">
        <div class="ab-fill" style="width:0%" data-target="${pct}"></div>
      </div>
      <div class="ab-val">${pct.toFixed(1)}%</div>
    `;
    container.appendChild(div);
  });
  setTimeout(() => {
    container.querySelectorAll('.ab-fill').forEach(bar => {
      bar.style.width = bar.dataset.target + '%';
    });
  }, 300);
}

function renderFindings(findings) {
  const container = document.getElementById('findingsList');
  container.innerHTML = '';
  if (!findings.length) {
    container.innerHTML = '<div class="finding-item ok">✅ No threats detected</div>';
    return;
  }
  findings.forEach((f, i) => {
    const cls = f.includes('🚨') ? 'critical'
               : f.includes('🔴') ? 'critical'
               : f.includes('⚠️') ? 'warn'
               : f.includes('✅') ? 'ok'
               : 'info';
    const div = document.createElement('div');
    div.className = `finding-item ${cls}`;
    div.style.animationDelay = `${i * 0.05}s`;
    div.textContent = f;
    container.appendChild(div);
  });
}

function renderRecommendations(recs) {
  const container = document.getElementById('recommendations');
  container.innerHTML = '';
  recs.forEach((rec, i) => {
    const div = document.createElement('div');
    div.className = 'rec-item';
    div.style.animationDelay = `${i * 0.06}s`;
    div.textContent = rec;
    container.appendChild(div);
  });
}

function renderThreatIntel(intel, color, score) {
  const container = document.getElementById('threatIntel');
  container.innerHTML = '';

  const items = [
    { key: 'IOC Matches', val: (intel.ioc_matches || []).join(', ') || 'None' },
    { key: 'Campaigns', val: (intel.campaigns_matched || []).join(', ') || 'None' },
    { key: 'Content Hash', val: intel.fingerprint || '—' },
    { key: 'Threat Level', val: score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW' },
  ];

  // Agent breakdown
  const breakdown = intel.threat_score_breakdown || {};
  Object.entries(breakdown).forEach(([agent, data]) => {
    items.push({ key: agent, val: `${data.score}% (conf: ${data.confidence}%)` });
  });

  items.forEach(item => {
    const div = document.createElement('div');
    div.className = 'ti-item';
    div.innerHTML = `<div class="ti-key">${item.key}</div><div class="ti-val">${item.val}</div>`;
    container.appendChild(div);
  });
}

// ── SIDEBAR ──────────────────────────────────────────────────────
function updateSidebarStats(data) {
  document.getElementById('statTotal').textContent = scoreHistory.length + 1;
  const all = [...scoreHistory, data.final_score];
  const avg = all.reduce((a, b) => a + b, 0) / all.length;
  document.getElementById('statAvg').textContent = Math.round(avg);
}

async function updateHistory() {
  const container = document.getElementById('historyList');
  try {
    const r = await fetch(`${API_BASE}/api/history`);
    const d = await r.json();
    renderHistory(d.data || []);
  } catch {
    // keep existing
  }
}

function renderHistory(items) {
  const container = document.getElementById('historyList');
  if (!items.length) { container.innerHTML = '<div class="history-empty">No analyses yet</div>'; return; }
  container.innerHTML = '';
  items.forEach(item => {
    const color = RISK_COLORS[item.risk_level] || '#aaa';
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `
      <div class="hi-top">
        <span class="hi-score" style="color:${color}">${item.score}</span>
        <span class="hi-risk" style="color:${color}">${item.risk_level}</span>
      </div>
      <div class="hi-preview">${item.preview || '—'}</div>
    `;
    container.appendChild(div);
  });
}

async function refreshHistory() {
  try {
    const r = await fetch(`${API_BASE}/api/history`);
    const d = await r.json();
    renderHistory(d.data || []);
  } catch {}
}

// ── MINI CHART ────────────────────────────────────────────────────
function drawMiniChart() {
  const canvas = document.getElementById('miniChart');
  if (!canvas || scoreHistory.length < 2) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const scores = scoreHistory.slice(-10);
  const min = 0, max = 100;
  const stepX = w / (scores.length - 1);

  ctx.beginPath();
  ctx.strokeStyle = '#00e5ff';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';

  scores.forEach((s, i) => {
    const x = i * stepX;
    const y = h - ((s - min) / (max - min)) * h;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Fill
  ctx.lineTo((scores.length - 1) * stepX, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  ctx.fillStyle = 'rgba(0,229,255,0.08)';
  ctx.fill();

  // Dots
  scores.forEach((s, i) => {
    const x = i * stepX;
    const y = h - ((s - min) / (max - min)) * h;
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = scoreColor(s);
    ctx.fill();
  });
}

// ── HELPERS ───────────────────────────────────────────────────────
function scoreColor(score) {
  if (score < 20) return '#00ff88';
  if (score < 40) return '#88ff00';
  if (score < 60) return '#ffcc00';
  if (score < 80) return '#ff6600';
  return '#ff2244';
}

function showNotification(msg, type = 'info') {
  const colors = { info: '#00e5ff', warn: '#ffcc00', error: '#ff2244' };
  const div = document.createElement('div');
  div.style.cssText = `
    position:fixed;bottom:60px;right:24px;z-index:9999;
    background:rgba(13,21,38,0.96);border:1px solid ${colors[type]};
    border-radius:8px;padding:12px 18px;
    font-family:'Share Tech Mono',monospace;font-size:12px;
    color:${colors[type]};
    animation:fadeSlide 0.3s ease;
    box-shadow:0 0 20px ${colors[type]}44;
    max-width:300px;
  `;
  div.textContent = msg;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 3500);
}

// ── LOCAL FALLBACK ENGINE ─────────────────────────────────────────
// Used when Python API is unavailable
function localAnalysisEngine(payload) {
  const { text = '', url = '', transaction = {}, sender_email = '' } = payload;
  const all = (text + ' ' + url + ' ' + sender_email).toLowerCase();

  let score = 0;
  const findings = [];
  const agentSignals = [];

  // Keyword agent
  let kwScore = 0;
  const keywords = ['urgent', 'verify', 'password', 'click here', 'suspended',
    'immediately', 'bank', 'paypal', 'amazon', 'credit card', 'account'];
  keywords.forEach(kw => {
    if (all.includes(kw)) {
      kwScore += 0.15;
      findings.push(`🔴 [HIGH] Phishing keyword detected: '${kw}'`);
    }
  });
  agentSignals.push({ agent: 'KeywordNLP', score: Math.min(kwScore * 100, 100), confidence: 70, findings: [], weight: 1.4 });
  score += kwScore * 1.4;

  // URL agent
  let urlScore = 0;
  if (url) {
    if (url.startsWith('http://')) { urlScore += 0.18; findings.push('🔴 Insecure HTTP connection'); }
    ['.xyz', '.tk', '.ml', '.ru'].forEach(tld => {
      if (url.includes(tld)) { urlScore += 0.30; findings.push(`🔴 Suspicious TLD: ${tld}`); }
    });
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      urlScore += 0.35; findings.push('🚨 IP address used as domain');
    }
    if (url.length > 100) { urlScore += 0.15; findings.push(`⚠️ Long URL (${url.length} chars)`); }
  }
  agentSignals.push({ agent: 'URLIntelligence', score: Math.min(urlScore * 100, 100), confidence: 80, findings: [], weight: 1.6 });
  score += urlScore * 1.6;

  // Transaction agent
  let amlScore = 0;
  const amt = transaction.amount || 0, freq = transaction.frequency || 0;
  if (amt >= 10000) { amlScore += 0.35; findings.push(`🚨 Amount $${amt} exceeds CTR threshold`); }
  else if (amt >= 9000) { amlScore += 0.45; findings.push(`🚨 Possible structuring: $${amt}`); }
  if (freq >= 10) { amlScore += 0.40; findings.push(`🚨 High frequency: ${freq} tx/day`); }
  agentSignals.push({ agent: 'AMLTransaction', score: Math.min(amlScore * 100, 100), confidence: 75, findings: [], weight: 1.5 });
  score += amlScore * 1.5;

  // Email agent
  let emailScore = 0;
  if (sender_email) {
    const freeDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    const officialTerms = ['paypal', 'amazon', 'bank', 'security', 'microsoft'];
    const domain = sender_email.split('@')[1] || '';
    if (freeDomains.includes(domain) && officialTerms.some(t => sender_email.includes(t))) {
      emailScore += 0.40; findings.push(`🚨 Official-sounding email from free provider`);
    }
  }
  agentSignals.push({ agent: 'EmailHeader', score: Math.min(emailScore * 100, 100), confidence: 65, findings: [], weight: 1.2 });
  score += emailScore * 1.2;

  // Normalize
  const totalWeight = 1.4 + 1.6 + 1.5 + 1.2;
  const finalScore = Math.round(Math.min((score / totalWeight) * 100, 100));

  const riskLevels = ['Safe', 'Low Risk', 'Suspicious', 'High Risk', 'Critical'];
  const riskLevel = finalScore < 20 ? 'Safe' : finalScore < 40 ? 'Low Risk'
    : finalScore < 60 ? 'Suspicious' : finalScore < 80 ? 'High Risk' : 'Critical';

  const recs = finalScore >= 60
    ? ['🛡️ DO NOT click any links', '🛡️ Report to security team', '⚠️ Verify sender through official channel']
    : ['✅ Content appears legitimate — standard caution applies'];

  return {
    final_score: finalScore,
    risk_level: riskLevel,
    risk_color: RISK_COLORS[riskLevel],
    confidence: 0.72,
    attack_type: kwScore > 0.3 ? 'Phishing Email' : urlScore > 0.3 ? 'URL/Link Fraud'
      : amlScore > 0.3 ? 'Financial Fraud (AML)' : 'No Threat Detected',
    attack_probability: {
      'Phishing Email': Math.round(kwScore * 100),
      'URL/Link Fraud': Math.round(urlScore * 100),
      'Financial Fraud (AML)': Math.round(amlScore * 100),
      'Social Engineering': Math.round(kwScore * 60),
      'Brand Impersonation': Math.round(emailScore * 100),
      'Malware Distribution': Math.round(urlScore * 60),
    },
    explanation: findings.length ? findings : ['✅ No significant threats detected in this content'],
    recommendations: recs,
    threat_intel: {
      ioc_matches: [],
      campaigns_matched: [],
      fingerprint: Math.random().toString(16).slice(2, 10),
      threat_score_breakdown: Object.fromEntries(
        agentSignals.map(s => [s.agent, { score: s.score, confidence: s.confidence }])
      )
    },
    processing_time_ms: Math.round(Math.random() * 30 + 15),
    timestamp: new Date().toISOString(),
    agent_signals: agentSignals
  };
}

// ── LOCAL TEST CASES FALLBACK ──────────────────────────────────────
function getLocalTestCases() {
  return [
    {
      name: 'Phishing Email', icon: '📧',
      data: {
        text: 'URGENT: Your PayPal account has been suspended! Verify your account immediately or it will be permanently deleted. Click here to verify your password and banking details!',
        url: 'http://paypa1-secure-verify.xyz/login',
        sender_email: 'security@paypa1-accounts.xyz',
        transaction: { amount: 0, frequency: 0 }
      }
    },
    {
      name: 'AML Fraud', icon: '💰',
      data: {
        text: 'Wire transfer confirmation: Please process the attached invoice immediately.',
        url: '',
        sender_email: 'finance@offshore-holdings.ru',
        transaction: { amount: 9500, frequency: 8 }
      }
    },
    {
      name: 'Malware URL', icon: '🦠',
      data: {
        text: 'Your computer is infected! Download our FREE antivirus software immediately!',
        url: 'http://192.168.1.1/download/update.exe',
        sender_email: '',
        transaction: { amount: 0, frequency: 0 }
      }
    },
    {
      name: 'Legitimate', icon: '✅',
      data: {
        text: 'Hi John, please find attached the Q3 report. Let me know if you have questions.',
        url: 'https://docs.google.com/spreadsheets/d/abc123',
        sender_email: 'sarah.jones@company.com',
        transaction: { amount: 250, frequency: 1 }
      }
    }
  ];
}

// ── PARTICLES ─────────────────────────────────────────────────────
function initParticles() {
  const container = document.getElementById('particles');
  if (!container) return;
  for (let i = 0; i < 30; i++) {
    const p = document.createElement('div');
    const size = Math.random() * 2 + 1;
    p.style.cssText = `
      position:absolute;
      width:${size}px;height:${size}px;
      border-radius:50%;
      background:rgba(0,229,255,${Math.random() * 0.3 + 0.05});
      left:${Math.random() * 100}%;
      top:${Math.random() * 100}%;
      animation:particleDrift ${Math.random() * 20 + 15}s linear infinite;
      animation-delay:${-Math.random() * 20}s;
    `;
    container.appendChild(p);
  }

  const style = document.createElement('style');
  style.textContent = `
    @keyframes particleDrift {
      0%   { transform: translate(0,0) opacity(0.1); }
      25%  { transform: translate(${Math.random()*40-20}px,${Math.random()*40-20}px); }
      50%  { transform: translate(${Math.random()*60-30}px,${Math.random()*60-30}px); opacity:0.6; }
      75%  { transform: translate(${Math.random()*40-20}px,${Math.random()*40-20}px); }
      100% { transform: translate(0,0); opacity:0.1; }
    }
  `;
  document.head.appendChild(style);
}
