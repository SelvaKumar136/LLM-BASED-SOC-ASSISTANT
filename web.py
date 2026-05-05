"""
Enterprise Portal — User-Facing Layer
======================================
Run with:  python web.py
Portal:    http://localhost:5000
SOC Dash:  http://localhost:5000/soc-dashboard
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, render_template_string, jsonify
from ingest.normalizer import normalize_alert
from agents.supervisor import run_investigation
from hitl.approval_queue import get_pending_actions, approve_action, deny_action
import threading
import queue
from datetime import datetime, timezone
from collections import deque

# ============================================================
# GLOBALS
# ============================================================
log_queue      = queue.Queue()
alert_history  = deque(maxlen=50)
processing_lock = threading.Lock()

# ============================================================
# BACKGROUND SOC WORKER
# ============================================================
def soc_worker():
    while True:
        log = log_queue.get()
        try:
            alert  = normalize_alert("enterprise_portal", log)
            result = run_investigation(alert)
            with processing_lock:
                alert_history.appendleft(result)
            print(f"\n[SOC] ✅ Investigation complete for alert: {alert.get('alert_id','')[:8]}")
        except Exception as e:
            print(f"\n[SOC] ❌ Pipeline error: {e}")
        finally:
            log_queue.task_done()

threading.Thread(target=soc_worker, daemon=True).start()

# ============================================================
# USER STORE
# ============================================================
USERS = {
    "jsmith":      "Welcome@123",
    "admin":       "Admin@123",
    "employee1":   "Emp@123",
    "mary.jones":  "Mary@456",
    "john.doe":    "John@Corp456",
}

# ============================================================
# ATTEMPT TRACKER  — keyed by USERNAME
# ============================================================
attempts          = {}   # { username: count }
lockout_threshold = 5    # lock account after 5 failures
soc_threshold     = 3    # alert SOC after 3 failures

app = Flask(__name__)
app.secret_key = "soc-demo-secret-key-2026"

# ============================================================
# LOGIN PAGE HTML
# ============================================================
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enterprise Access Portal</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #05070f; --card: #0f1629;
    --border: rgba(56,189,248,0.12);
    --accent: #38bdf8; --accent2: #818cf8;
    --danger: #f87171; --success: #4ade80;
    --text: #e2e8f0; --muted: #64748b;
  }
  body {
    font-family: 'DM Sans', sans-serif;
    background: var(--bg); color: var(--text);
    min-height: 100vh; display: flex; overflow: hidden;
  }
  body::before {
    content: ''; position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(56,189,248,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(56,189,248,0.03) 1px, transparent 1px);
    background-size: 40px 40px; pointer-events: none;
  }
  .left {
    width: 52%;
    background: linear-gradient(135deg, #080c1a 0%, #0b1128 100%);
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    justify-content: center; padding: 64px 72px;
    position: relative; overflow: hidden;
  }
  .left::after {
    content: ''; position: absolute;
    width: 500px; height: 500px; border-radius: 50%;
    background: radial-gradient(circle, rgba(56,189,248,0.07) 0%, transparent 70%);
    bottom: -150px; left: -100px; pointer-events: none;
  }
  .logo-row { display: flex; align-items: center; gap: 12px; margin-bottom: 48px; }
  .logo-icon {
    width: 40px; height: 40px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 10px; display: flex; align-items: center;
    justify-content: center; font-size: 20px;
  }
  .logo-text {
    font-size: 15px; font-weight: 700;
    letter-spacing: 2px; text-transform: uppercase; color: var(--accent);
  }
  .left h1 { font-size: 42px; font-weight: 700; line-height: 1.2; margin-bottom: 16px; }
  .left h1 span { color: var(--accent); }
  .left p { color: var(--muted); font-size: 15px; line-height: 1.7; max-width: 360px; margin-bottom: 40px; }
  .features { display: flex; flex-direction: column; gap: 14px; }
  .feature {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 16px;
    background: rgba(56,189,248,0.05);
    border: 1px solid var(--border); border-radius: 10px;
    font-size: 13px; color: #94a3b8;
  }
  .right { width: 48%; display: flex; align-items: center; justify-content: center; padding: 40px; }
  .card {
    width: 100%; max-width: 400px;
    background: var(--card); border: 1px solid var(--border);
    border-radius: 18px; padding: 40px;
    box-shadow: 0 25px 60px rgba(0,0,0,0.5);
  }
  .card-header { margin-bottom: 32px; }
  .card-header h2 { font-size: 24px; font-weight: 700; margin-bottom: 6px; }
  .card-header p  { font-size: 13px; color: var(--muted); }
  .field { margin-bottom: 16px; }
  .field label {
    display: block; font-size: 12px; font-weight: 500;
    color: var(--muted); letter-spacing: 0.5px;
    text-transform: uppercase; margin-bottom: 8px;
  }
  .field input {
    width: 100%; padding: 12px 14px;
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border); border-radius: 9px;
    color: var(--text); font-family: 'DM Mono', monospace;
    font-size: 14px; outline: none; transition: border 0.2s;
  }
  .field input:focus { border-color: var(--accent); }
  .btn {
    width: 100%; padding: 13px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border: none; border-radius: 9px; color: #05070f;
    font-family: 'DM Sans', sans-serif; font-weight: 700;
    font-size: 14px; cursor: pointer; transition: opacity 0.2s, transform 0.1s;
    margin-top: 8px;
  }
  .btn:hover { opacity: 0.9; } .btn:active { transform: scale(0.99); }
  .msg {
    margin-top: 18px; padding: 11px 14px; border-radius: 8px;
    font-size: 13px; text-align: center; font-weight: 500;
  }
  .msg.error   { background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.25); color: var(--danger); }
  .msg.success { background: rgba(74,222,128,0.1);  border: 1px solid rgba(74,222,128,0.25);  color: var(--success); }
  .msg.warning { background: rgba(251,191,36,0.1);  border: 1px solid rgba(251,191,36,0.25);  color: #fbbf24; }
  .divider { height: 1px; background: var(--border); margin: 24px 0; }
  .footer { font-size: 11px; color: var(--muted); text-align: center; }
  @media (max-width: 768px) {
    body { flex-direction: column; overflow: auto; }
    .left  { width: 100%; padding: 40px 32px; }
    .right { width: 100%; padding: 24px; }
  }
</style>
</head>
<body>
<div class="left">
  <div class="logo-row">
    <div class="logo-icon">🏢</div>
    <span class="logo-text">CorpSec</span>
  </div>
  <h1>Enterprise<br><span>Access Portal</span></h1>
  <p>Secure, monitored access to internal systems and corporate resources. All activity is logged and monitored.</p>
  <div class="features">
    <div class="feature">🔒 End-to-end encrypted sessions</div>
    <div class="feature">📊 Real-time security monitoring</div>
    <div class="feature">🌐 Single sign-on enabled</div>
  </div>
</div>
<div class="right">
  <div class="card">
    <div class="card-header">
      <h2>Sign In</h2>
      <p>Enter your corporate credentials to continue</p>
    </div>
    <form method="POST">
      <div class="field">
        <label>Username</label>
        <input name="username" placeholder="e.g. jsmith" autocomplete="off" required>
      </div>
      <div class="field">
        <label>Password</label>
        <input name="password" type="password" placeholder="••••••••" required>
      </div>
      <button class="btn" type="submit">Authenticate →</button>
    </form>
    {% if message %}
    <div class="msg {{ msg_class }}">{{ message }}</div>
    {% endif %}
    <div class="divider"></div>
    <div class="footer">© 2026 CorpSec Enterprise Systems · <a href="#" style="color:#38bdf8;text-decoration:none;">Help</a></div>
  </div>
</div>
</body>
</html>
"""

# ============================================================
# SOC DASHBOARD HTML
# ============================================================
SOC_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Analyst Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #02040a; --card: #0a0e1a;
    --border: rgba(34,197,94,0.15);
    --green: #22c55e; --cyan: #06b6d4;
    --orange: #f97316; --red: #ef4444;
    --yellow: #eab308; --purple: #a855f7;
    --text: #e2e8f0; --muted: #475569; --dim: #1e293b;
  }
  body { font-family: 'IBM Plex Sans', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  body::before {
    content: ''; position: fixed; inset: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
    pointer-events: none; z-index: 9999;
  }
  nav {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 28px; background: rgba(7,9,21,0.95);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100; backdrop-filter: blur(20px);
  }
  .nav-brand { font-family: 'IBM Plex Mono', monospace; font-size: 14px; font-weight: 600; color: var(--green); }
  .nav-brand::before { content: '● '; animation: blink 1.5s infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
  .nav-right { display: flex; align-items: center; gap: 20px; }
  .nav-badge {
    padding: 4px 10px; border-radius: 20px;
    font-size: 11px; font-family: 'IBM Plex Mono', monospace;
    font-weight: 500; border: 1px solid; letter-spacing: 0.5px;
  }
  .nav-badge.green  { border-color: var(--green);  color: var(--green);  background: rgba(34,197,94,0.1); }
  .nav-badge.red    { border-color: var(--red);    color: var(--red);    background: rgba(239,68,68,0.1); }
  .nav-badge.orange { border-color: var(--orange); color: var(--orange); background: rgba(249,115,22,0.1); }
  .nav-time { font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--muted); }
  .layout { display: grid; grid-template-columns: 260px 1fr; min-height: calc(100vh - 54px); }
  aside {
    background: var(--card); border-right: 1px solid var(--border);
    padding: 24px 16px; display: flex; flex-direction: column; gap: 24px;
  }
  .sidebar-section h4 {
    font-family: 'IBM Plex Mono', monospace; font-size: 10px;
    letter-spacing: 2px; text-transform: uppercase; color: var(--muted);
    margin-bottom: 12px; padding-left: 8px;
  }
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .stat { background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 10px; padding: 12px; text-align: center; }
  .stat .val { font-family: 'IBM Plex Mono', monospace; font-size: 22px; font-weight: 600; }
  .stat .lbl { font-size: 10px; color: var(--muted); margin-top: 2px; letter-spacing: 0.5px; }
  .stat.red    .val { color: var(--red); }
  .stat.orange .val { color: var(--orange); }
  .stat.yellow .val { color: var(--yellow); }
  .stat.green  .val { color: var(--green); }
  .action-item {
    background: rgba(239,68,68,0.07); border: 1px solid rgba(239,68,68,0.2);
    border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; font-size: 12px;
  }
  .action-item .atype { font-family: 'IBM Plex Mono', monospace; font-weight: 600; color: var(--red); font-size: 11px; margin-bottom: 4px; }
  .action-item .adetail { color: #94a3b8; font-size: 11px; }
  .action-btns { display: flex; gap: 6px; margin-top: 8px; }
  .abtn { flex: 1; padding: 5px; border: none; border-radius: 5px; font-size: 11px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
  .abtn.approve { background: rgba(34,197,94,0.2); color: var(--green); border: 1px solid rgba(34,197,94,0.3); }
  .abtn.deny    { background: rgba(239,68,68,0.2); color: var(--red);   border: 1px solid rgba(239,68,68,0.3); }
  .abtn:hover   { opacity: 0.75; }
  .no-actions { font-size: 12px; color: var(--muted); text-align: center; padding: 12px; }
  main { padding: 28px; overflow-y: auto; }
  .page-title { font-size: 20px; font-weight: 700; margin-bottom: 24px; display: flex; align-items: center; gap: 10px; }
  .page-title span { color: var(--green); font-family: 'IBM Plex Mono', monospace; font-size: 14px; }
  .alert-feed { display: flex; flex-direction: column; gap: 14px; }
  .alert-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; transition: border-color 0.2s; }
  .alert-card:hover { border-color: rgba(34,197,94,0.3); }
  .alert-card.critical { border-left: 3px solid var(--red); }
  .alert-card.high     { border-left: 3px solid var(--orange); }
  .alert-card.medium   { border-left: 3px solid var(--yellow); }
  .alert-card.low      { border-left: 3px solid var(--green); }
  .card-header-row {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 18px; background: rgba(255,255,255,0.02);
    border-bottom: 1px solid var(--border); cursor: pointer;
  }
  .card-header-row:hover { background: rgba(255,255,255,0.03); }
  .alert-title { font-weight: 600; font-size: 14px; }
  .alert-meta  { font-size: 11px; color: var(--muted); margin-top: 3px; font-family: 'IBM Plex Mono', monospace; }
  .badge { padding: 3px 10px; border-radius: 20px; font-size: 10px; font-weight: 700; font-family: 'IBM Plex Mono', monospace; letter-spacing: 1px; text-transform: uppercase; }
  .badge.critical { background: rgba(239,68,68,0.2); color: var(--red);    border: 1px solid rgba(239,68,68,0.3); }
  .badge.high     { background: rgba(249,115,22,0.2); color: var(--orange); border: 1px solid rgba(249,115,22,0.3); }
  .badge.medium   { background: rgba(234,179,8,0.2);  color: var(--yellow); border: 1px solid rgba(234,179,8,0.3); }
  .badge.low      { background: rgba(34,197,94,0.2);  color: var(--green);  border: 1px solid rgba(34,197,94,0.3); }
  .card-body { display: none; padding: 18px; }
  .card-body.open { display: block; }
  .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .info-item label { font-size: 10px; color: var(--muted); letter-spacing: 1px; text-transform: uppercase; display: block; margin-bottom: 4px; }
  .info-item span  { font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--cyan); }
  .mitre-badge {
    display: inline-block; padding: 4px 10px; border-radius: 6px;
    background: rgba(168,85,247,0.1); border: 1px solid rgba(168,85,247,0.3);
    color: var(--purple); font-size: 11px; font-weight: 600; font-family: 'IBM Plex Mono', monospace;
  }
  .section-label {
    font-size: 10px; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase;
    color: var(--muted); margin: 14px 0 8px; border-bottom: 1px solid var(--dim); padding-bottom: 6px;
  }
  .report-text {
    font-size: 12px; line-height: 1.75; color: #94a3b8;
    background: rgba(0,0,0,0.3); border-radius: 8px; padding: 12px;
    border: 1px solid var(--dim); max-height: 220px; overflow-y: auto;
    font-family: 'IBM Plex Mono', monospace; white-space: pre-wrap;
  }
  .empty-state { text-align: center; padding: 80px 40px; color: var(--muted); }
  .empty-state .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }
  .empty-state p { font-size: 14px; }
  .refresh-btn {
    padding: 8px 18px; background: rgba(34,197,94,0.1);
    border: 1px solid rgba(34,197,94,0.3); border-radius: 7px; color: var(--green);
    font-size: 12px; font-weight: 600; cursor: pointer;
    font-family: 'IBM Plex Mono', monospace; letter-spacing: 0.5px; transition: opacity 0.2s;
  }
  .refresh-btn:hover { opacity: 0.75; }
  .fp-tag {
    color: var(--yellow); font-size: 11px; font-weight: 600;
    background: rgba(234,179,8,0.1); border: 1px solid rgba(234,179,8,0.2);
    padding: 2px 8px; border-radius: 4px;
  }
  .attack-tag {
    display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: 11px;
    font-weight: 600; font-family: 'IBM Plex Mono', monospace;
    background: rgba(6,182,212,0.1); border: 1px solid rgba(6,182,212,0.3); color: var(--cyan);
    margin-left: 6px;
  }
</style>
</head>
<body>
<nav>
  <div class="nav-brand">AutSOC · ANALYST DASHBOARD</div>
  <div class="nav-right">
    <span class="nav-badge green">SYSTEM ONLINE</span>
    {% if pending_count > 0 %}
    <span class="nav-badge red">{{ pending_count }} PENDING</span>
    {% endif %}
    <span class="nav-badge orange">INTERNAL ONLY</span>
    <span class="nav-time" id="clock"></span>
  </div>
</nav>

<div class="layout">
  <aside>
    <div class="sidebar-section">
      <h4>Session Stats</h4>
      <div class="stat-grid">
        <div class="stat">               <div class="val">{{ total }}</div>    <div class="lbl">TOTAL</div></div>
        <div class="stat red">           <div class="val">{{ critical }}</div> <div class="lbl">CRITICAL</div></div>
        <div class="stat orange">        <div class="val">{{ high }}</div>     <div class="lbl">HIGH</div></div>
        <div class="stat yellow">        <div class="val">{{ medium }}</div>   <div class="lbl">MEDIUM</div></div>
        <div class="stat green">         <div class="val">{{ low }}</div>      <div class="lbl">LOW</div></div>
        <div class="stat">               <div class="val" style="color:var(--muted)">{{ fp }}</div><div class="lbl">FALSE POS</div></div>
      </div>
    </div>

    <div class="sidebar-section">
      <h4>Pending HITL Actions</h4>
      {% if pending_actions %}
        {% for i, action in pending_actions %}
        <div class="action-item">
          <div class="atype">{{ action.action_type | upper }}</div>
          <div class="adetail">
            {% if action.action_type == 'block_ip' %}IP: {{ action.ip }}{% endif %}
            {% if action.action_type == 'isolate_host' %}Host: {{ action.hostname }}{% endif %}
            <br>{{ action.get('reason','')[:60] }}
          </div>
          <div class="action-btns">
            <button class="abtn approve" onclick="handleAction('approve', {{ i }})">✓ Approve</button>
            <button class="abtn deny"    onclick="handleAction('deny',    {{ i }})">✗ Deny</button>
          </div>
        </div>
        {% endfor %}
      {% else %}
        <div class="no-actions">✅ No pending actions</div>
      {% endif %}
    </div>

    <div class="sidebar-section" style="margin-top:auto;">
      <h4>Pipeline</h4>
      <div style="font-size:11px;color:var(--muted);line-height:2;font-family:'IBM Plex Mono',monospace;">
        Triage → Investigate<br>→ Respond → Memory
      </div>
    </div>
  </aside>

  <main>
    <div class="page-title">
      Alert Feed
      <span>{{ total }} alerts</span>
      <button class="refresh-btn" onclick="location.reload()">⟳ Refresh</button>
    </div>

    {% if alerts %}
    <div class="alert-feed">
      {% for rec in alerts %}
      {% set triage = rec.get('triage', {}) %}
      {% set alert  = rec.get('alert',  {}) %}
      {% set sev    = triage.get('severity', 'Medium') | lower %}

      <div class="alert-card {{ sev }}">
        <div class="card-header-row" onclick="toggle(this)">
          <div>
            <div class="alert-title">
              {{ alert.get('title', 'Unknown Alert') }}
              {% if alert.get('attack_pattern') %}
              <span class="attack-tag">{{ alert.get('attack_pattern','').replace('_',' ').upper() }}</span>
              {% endif %}
            </div>
            <div class="alert-meta">
              {{ alert.get('src_ip', 'N/A') }} · {{ alert.get('username', 'N/A') }} ·
              {{ alert.get('timestamp', '')[:19] }}
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            {% if triage.get('false_positive') %}
            <span class="fp-tag">FALSE POS</span>
            {% endif %}
            <span class="badge {{ sev }}">{{ triage.get('severity','?') }}</span>
            <span style="color:var(--muted);font-size:12px;">▼</span>
          </div>
        </div>

        <div class="card-body">
          <div class="info-grid">
            <div class="info-item"><label>Threat Category</label><span>{{ triage.get('threat_category','N/A') }}</span></div>
            <div class="info-item"><label>MITRE Tactic</label><span>{{ triage.get('mitre_tactic','N/A') }}</span></div>
            <div class="info-item"><label>Source IP</label><span>{{ alert.get('src_ip','N/A') }}</span></div>
            <div class="info-item"><label>Username</label><span>{{ alert.get('username','N/A') }}</span></div>
            <div class="info-item"><label>Failed Logins</label><span>{{ alert.get('failed_login_count','N/A') }}</span></div>
            <div class="info-item"><label>Accounts Targeted</label><span>{{ alert.get('accounts_targeted_by_ip','N/A') }}</span></div>
            <div class="info-item"><label>Attack Pattern</label><span>{{ alert.get('attack_pattern','N/A') }}</span></div>
            <div class="info-item"><label>FP Confidence</label><span>{{ "%.0f%%"|format(triage.get('fp_confidence',0)*100) }}</span></div>
          </div>

          <div>
            <span class="mitre-badge">🎯 {{ triage.get('mitre_technique','N/A') }}</span>
          </div>

          <div class="section-label">Triage Reasoning</div>
          <div class="report-text">{{ triage.get('reasoning','N/A') }}</div>

          {% if rec.get('investigation') %}
          <div class="section-label">Investigation Report</div>
          <div class="report-text">{{ rec.get('investigation','') }}</div>
          {% endif %}

          {% if rec.get('response') %}
          <div class="section-label">Response Actions</div>
          <div class="report-text">{{ rec.get('response','') }}</div>
          {% endif %}
        </div>
      </div>
      {% endfor %}
    </div>

    {% else %}
    <div class="empty-state">
      <div class="icon">📡</div>
      <p>No alerts yet. Go to <a href="/" style="color:var(--cyan);">Enterprise Portal</a>
         and enter wrong credentials 3+ times to trigger the SOC pipeline.</p>
    </div>
    {% endif %}
  </main>
</div>

<script>
  function tick() {
    document.getElementById('clock').textContent =
      new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';
  }
  tick(); setInterval(tick, 1000);

  function toggle(header) {
    const body = header.nextElementSibling;
    body.classList.toggle('open');
    const arrow = header.querySelector('span:last-child');
    arrow.textContent = body.classList.contains('open') ? '▲' : '▼';
  }

  async function handleAction(cmd, idx) {
    const res  = await fetch(`/soc-api/action/${cmd}/${idx}`, {method:'POST'});
    const data = await res.json();
    if (data.ok) location.reload();
    else alert('Error: ' + data.error);
  }
</script>
</body>
</html>
"""

# ============================================================
# ROUTES
# ============================================================

@app.route("/", methods=["GET", "POST"])
def login():
    message   = ""
    msg_class = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        ip       = request.remote_addr

        # Initialise counters if first time seeing this username
        attempts.setdefault(username, 0)

        # ---- LOCKED OUT ----
        if attempts[username] >= lockout_threshold:
            message   = f"⚠️ Account locked after {lockout_threshold} failed attempts. Contact IT."
            msg_class = "warning"

        # ---- VALID LOGIN ----
        elif username in USERS and USERS[username] == password:
            attempts[username] = 0   # reset on success
            message   = "✅ Access Granted. Redirecting to portal..."
            msg_class = "success"

        # ---- FAILED LOGIN ----
        else:
            attempts[username] += 1
            remaining = lockout_threshold - attempts[username]

            if remaining <= 0:
                message   = "⚠️ Too many failed attempts. Account locked."
                msg_class = "warning"
            else:
                message   = f"❌ Invalid credentials. {remaining} attempt(s) remaining."
                msg_class = "error"

            print(f"\n[PORTAL] ⚠️  Failed login — user: {username}, ip: {ip}, attempt #{attempts[username]}")

            # Only alert SOC after hitting the threshold on the SAME account
            if attempts[username] >= soc_threshold:
                # Count how many distinct usernames this IP has targeted
                accounts_hit = len([u for u, c in attempts.items() if c >= 1])
                pattern      = "password_spraying" if accounts_hit > 1 else "brute_force"

                log = {
                    "title":                  "Brute Force Login Detected",
                    "src_ip":                 ip,
                    "hostname":               "enterprise-web-portal",
                    "username":               username,
                    "process_name":           "auth_portal",
                    "failed_login_count":     attempts[username],
                    "accounts_targeted_by_ip": accounts_hit,
                    "attack_pattern":         pattern,
                    "timestamp":              datetime.now(timezone.utc).isoformat(),
                }
                print(f"[PORTAL] 🚨 SOC alert triggered — pattern: {pattern}, accounts hit: {accounts_hit}")
                log_queue.put(log)

    return render_template_string(LOGIN_PAGE, message=message, msg_class=msg_class)


@app.route("/soc-dashboard")
def soc_dashboard():
    with processing_lock:
        alerts = list(alert_history)

    pending_raw     = get_pending_actions()
    pending_actions = list(enumerate(pending_raw))

    total    = len(alerts)
    critical = sum(1 for a in alerts if a.get("triage",{}).get("severity") == "Critical")
    high     = sum(1 for a in alerts if a.get("triage",{}).get("severity") == "High")
    medium   = sum(1 for a in alerts if a.get("triage",{}).get("severity") == "Medium")
    low      = sum(1 for a in alerts if a.get("triage",{}).get("severity") == "Low")
    fp       = sum(1 for a in alerts if a.get("triage",{}).get("false_positive") is True)

    return render_template_string(
        SOC_DASHBOARD,
        alerts=alerts,
        pending_actions=pending_actions,
        pending_count=len(pending_raw),
        total=total, critical=critical, high=high,
        medium=medium, low=low, fp=fp,
    )


@app.route("/soc-api/action/<cmd>/<int:idx>", methods=["POST"])
def soc_action(cmd, idx):
    try:
        if   cmd == "approve": result = approve_action(idx)
        elif cmd == "deny":    result = deny_action(idx)
        else: return jsonify({"ok": False, "error": "Unknown command"})

        if "error" in result:
            return jsonify({"ok": False, "error": result["error"]})
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/soc-api/alerts")
def soc_alerts_json():
    with processing_lock:
        data = list(alert_history)
    return jsonify(data)


@app.route("/health")
def health():
    return jsonify({"status": "running", "queue_size": log_queue.qsize()})


# ============================================================
# ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print("  🏢  Enterprise Portal  →  http://localhost:5000")
    print("  🛡️   SOC Dashboard     →  http://localhost:5000/soc-dashboard")
    print("  ❤️   Health            →  http://localhost:5000/health")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)