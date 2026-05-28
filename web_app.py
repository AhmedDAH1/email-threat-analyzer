#!/usr/bin/env python3
"""
web_app.py — Web interface for the Email Threat Analyzer.

A thin presentation layer over the existing analysis engine
(analyzer/engine.py). Lets a visitor analyze a bundled sample email or
paste their own raw .eml content and see a rendered phishing report.

Run locally:   python3 web_app.py
Then open:     http://localhost:8000

Environment variables:
    PORT            Port to bind (default 8000)
    HOST            Interface to bind (default 127.0.0.1; set 0.0.0.0 in Docker)
    DEMO_MODE       If "1", disables free-text paste (sample-only) — unused by
                    default; the engine is safe either way since nothing is
                    written to disk and VirusTotal is disabled in the web app.
"""

import os
import glob
from flask import Flask, request, jsonify, render_template_string

from analyzer.engine import analyze_raw

app = Flask(__name__)

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples", "real")
MAX_EML_BYTES = 1_000_000  # 1 MB cap on pasted content


def list_samples():
    """Return [{id, label}] for each bundled sample .eml file."""
    out = []
    for path in sorted(glob.glob(os.path.join(SAMPLES_DIR, "*.eml"))):
        name = os.path.basename(path)
        stem = name[:-4]  # drop .eml
        label = stem.replace("_", " ").title()
        out.append({"id": name, "label": label})
    return out


def load_sample(sample_id: str) -> str | None:
    """Safely load a bundled sample by filename. Returns None if not found."""
    # Prevent path traversal: only allow plain .eml basenames
    if "/" in sample_id or "\\" in sample_id or not sample_id.endswith(".eml"):
        return None
    path = os.path.join(SAMPLES_DIR, sample_id)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def result_to_dict(result) -> dict:
    """Serialize a ScanResult for the frontend."""
    return {
        "threat_score": result.threat_score,
        "threat_level": result.threat_level,
        "scanned_at": result.scanned_at,
        "email": {
            "subject": result.email.subject or "(no subject)",
            "sender": result.email.sender or "(unknown)",
            "reply_to": result.email.reply_to or "—",
            "date": result.email.date or "—",
            "url_count": len(result.email.urls),
            "attachment_count": len(result.email.attachments),
        },
        "indicators": [
            {
                "category": ind.category,
                "name": ind.name,
                "description": ind.description,
                "severity": ind.severity,
                "evidence": ind.evidence,
            }
            for ind in sorted(result.indicators, key=lambda i: i.severity, reverse=True)
        ],
    }


@app.route("/")
def index():
    return render_template_string(PAGE, samples=list_samples())


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    raw = None

    sample_id = data.get("sample")
    if sample_id:
        raw = load_sample(sample_id)
        if raw is None:
            return jsonify({"error": "Unknown sample."}), 400
    else:
        raw = data.get("raw", "")
        if not raw or not raw.strip():
            return jsonify({"error": "No email content provided."}), 400
        if len(raw.encode("utf-8")) > MAX_EML_BYTES:
            return jsonify({"error": "Email content too large (1 MB limit)."}), 400

    # VirusTotal intentionally disabled in the web app (no API key, rate limits).
    try:
        result = analyze_raw(raw, vt_api_key=None)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500

    return jsonify(result_to_dict(result))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Threat Analyzer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e14;
    --bg-panel: #11161f;
    --bg-elev: #161c27;
    --border: #232b38;
    --border-bright: #313c4e;
    --text: #d6dde8;
    --text-dim: #7d8898;
    --text-faint: #4f5867;
    --green: #2ecc71;
    --amber: #f5a623;
    --orange: #ff7849;
    --red: #ff4d4d;
    --crit: #ff2e63;
    --accent: #38bdf8;
    --mono: 'IBM Plex Mono', ui-monospace, monospace;
    --display: 'Space Grotesk', sans-serif;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
    background-image:
      repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.012) 2px, rgba(255,255,255,0.012) 3px);
  }
  .wrap { max-width: 940px; margin: 0 auto; padding: 40px 24px 80px; }

  header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
  .eyebrow { color: var(--accent); font-size: 12px; letter-spacing: 3px; text-transform: uppercase; }
  h1 { font-family: var(--display); font-size: 34px; font-weight: 700; letter-spacing: -0.5px; margin: 6px 0; }
  .sub { color: var(--text-dim); font-size: 13px; max-width: 620px; }
  .sub a { color: var(--accent); text-decoration: none; }
  .sub a:hover { text-decoration: underline; }

  .panel { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 8px; padding: 22px; margin-bottom: 20px; }
  .panel-title { font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: var(--text-faint); margin-bottom: 14px; }

  .tabs { display: flex; gap: 4px; margin-bottom: 16px; }
  .tab { padding: 8px 16px; background: var(--bg-elev); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; color: var(--text-dim); font-size: 13px; transition: all 0.15s; }
  .tab.active { color: var(--bg); background: var(--accent); border-color: var(--accent); font-weight: 600; }

  select, textarea {
    width: 100%; background: var(--bg); border: 1px solid var(--border-bright);
    color: var(--text); font-family: var(--mono); font-size: 13px; padding: 12px;
    border-radius: 6px; outline: none;
  }
  select:focus, textarea:focus { border-color: var(--accent); }
  textarea { min-height: 200px; resize: vertical; line-height: 1.5; }

  .btn {
    margin-top: 14px; background: var(--accent); color: var(--bg); border: none;
    font-family: var(--mono); font-weight: 700; font-size: 14px; letter-spacing: 0.5px;
    padding: 12px 28px; border-radius: 6px; cursor: pointer; transition: opacity 0.15s;
  }
  .btn:hover { opacity: 0.88; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .hidden { display: none; }

  /* Report */
  #report { margin-top: 28px; }
  .score-row { display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }
  .gauge { width: 130px; height: 130px; position: relative; flex-shrink: 0; }
  .gauge svg { transform: rotate(-90deg); }
  .gauge .num { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .gauge .num b { font-family: var(--display); font-size: 30px; line-height: 1; }
  .gauge .num span { font-size: 10px; color: var(--text-faint); letter-spacing: 1px; }
  .verdict { flex: 1; min-width: 200px; }
  .level-badge { display: inline-block; font-family: var(--display); font-weight: 700; font-size: 22px; padding: 6px 18px; border-radius: 6px; letter-spacing: 1px; }
  .verdict .meta { color: var(--text-dim); font-size: 12px; margin-top: 10px; }

  .email-summary { margin-top: 22px; display: grid; grid-template-columns: auto 1fr; gap: 6px 18px; font-size: 13px; }
  .email-summary dt { color: var(--text-faint); }
  .email-summary dd { color: var(--text); word-break: break-word; }

  .ind { border-left: 3px solid var(--border-bright); background: var(--bg-elev); padding: 12px 16px; border-radius: 0 6px 6px 0; margin-bottom: 10px; }
  .ind-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .ind-name { font-weight: 600; }
  .ind-cat { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-faint); border: 1px solid var(--border-bright); padding: 1px 7px; border-radius: 4px; }
  .ind-sev { margin-left: auto; font-size: 11px; color: var(--text-dim); }
  .ind-desc { color: var(--text-dim); font-size: 13px; margin-top: 5px; }
  .ind-ev { color: var(--accent); font-size: 12px; margin-top: 6px; word-break: break-all; background: var(--bg); padding: 6px 10px; border-radius: 4px; }
  .clean-msg { text-align: center; padding: 30px; color: var(--green); }

  .err { color: var(--red); padding: 12px; border: 1px solid var(--red); border-radius: 6px; margin-top: 14px; }
  .loading { color: var(--text-dim); margin-top: 18px; }
  footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--text-faint); font-size: 12px; }
  footer a { color: var(--text-dim); text-decoration: none; }
  footer a:hover { color: var(--accent); }
  .note { font-size: 11px; color: var(--text-faint); margin-top: 8px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="eyebrow">// PHISHING DETECTION ENGINE</div>
    <h1>Email Threat Analyzer</h1>
    <div class="sub">
      Paste a raw <code>.eml</code> file or select a bundled sample. The engine runs
      header, URL, attachment, and content analyzers, then computes a 0–100 threat score.
      Built by <a href="https://github.com/AhmedDAH1/email-threat-analyzer" target="_blank">Ahmed Dahdouh</a>.
    </div>
  </header>

  <div class="panel">
    <div class="tabs">
      <div class="tab active" id="tab-sample" onclick="switchTab('sample')">Bundled sample</div>
      <div class="tab" id="tab-paste" onclick="switchTab('paste')">Paste your own</div>
    </div>

    <div id="mode-sample">
      <div class="panel-title">Select a sample email</div>
      <select id="sample-select">
        {% for s in samples %}
        <option value="{{ s.id }}">{{ s.label }}</option>
        {% endfor %}
      </select>
    </div>

    <div id="mode-paste" class="hidden">
      <div class="panel-title">Paste raw .eml content</div>
      <textarea id="raw-input" placeholder="From: ...&#10;Subject: ...&#10;...paste full email source here..."></textarea>
      <div class="note">Processed in memory. Nothing is stored. VirusTotal lookups are disabled in this hosted demo.</div>
    </div>

    <button class="btn" id="analyze-btn" onclick="analyze()">▶ Analyze</button>
    <div id="error-box"></div>
    <div id="loading" class="loading hidden">Running analyzers…</div>
  </div>

  <div id="report"></div>

  <footer>
    Email Threat Analyzer — a portfolio project.
    <a href="https://github.com/AhmedDAH1/email-threat-analyzer" target="_blank">Source on GitHub →</a>
  </footer>
</div>

<script>
let mode = 'sample';

function switchTab(m) {
  mode = m;
  document.getElementById('tab-sample').classList.toggle('active', m === 'sample');
  document.getElementById('tab-paste').classList.toggle('active', m === 'paste');
  document.getElementById('mode-sample').classList.toggle('hidden', m !== 'sample');
  document.getElementById('mode-paste').classList.toggle('hidden', m !== 'paste');
}

const LEVEL_COLORS = {
  CLEAN: 'var(--green)', LOW: 'var(--amber)', MEDIUM: 'var(--orange)',
  HIGH: 'var(--red)', CRITICAL: 'var(--crit)'
};

async function analyze() {
  const btn = document.getElementById('analyze-btn');
  const errBox = document.getElementById('error-box');
  const loading = document.getElementById('loading');
  const report = document.getElementById('report');
  errBox.innerHTML = '';
  report.innerHTML = '';
  loading.classList.remove('hidden');
  btn.disabled = true;

  let payload = {};
  if (mode === 'sample') {
    payload.sample = document.getElementById('sample-select').value;
  } else {
    payload.raw = document.getElementById('raw-input').value;
  }

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      errBox.innerHTML = '<div class="err">' + (data.error || 'Analysis failed.') + '</div>';
      return;
    }
    renderReport(data);
  } catch (e) {
    errBox.innerHTML = '<div class="err">Network error: ' + e.message + '</div>';
  } finally {
    loading.classList.add('hidden');
    btn.disabled = false;
  }
}

function renderReport(data) {
  const color = LEVEL_COLORS[data.threat_level] || 'var(--text-dim)';
  const score = data.threat_score;
  const circ = 2 * Math.PI * 54;
  const offset = circ * (1 - score / 100);

  let indHtml = '';
  if (data.indicators.length === 0) {
    indHtml = '<div class="clean-msg">✓ No suspicious indicators detected.</div>';
  } else {
    for (const ind of data.indicators) {
      indHtml += `
        <div class="ind" style="border-left-color:${color}">
          <div class="ind-head">
            <span class="ind-name">${esc(ind.name)}</span>
            <span class="ind-cat">${esc(ind.category)}</span>
            <span class="ind-sev">severity ${ind.severity}/10</span>
          </div>
          <div class="ind-desc">${esc(ind.description)}</div>
          ${ind.evidence ? `<div class="ind-ev">${esc(ind.evidence)}</div>` : ''}
        </div>`;
    }
  }

  document.getElementById('report').innerHTML = `
    <div class="panel">
      <div class="panel-title">Threat assessment</div>
      <div class="score-row">
        <div class="gauge">
          <svg width="130" height="130">
            <circle cx="65" cy="65" r="54" stroke="var(--border)" stroke-width="10" fill="none"/>
            <circle cx="65" cy="65" r="54" stroke="${color}" stroke-width="10" fill="none"
              stroke-dasharray="${circ}" stroke-dashoffset="${offset}" stroke-linecap="round"/>
          </svg>
          <div class="num"><b style="color:${color}">${score}</b><span>/ 100</span></div>
        </div>
        <div class="verdict">
          <span class="level-badge" style="background:${color}22;color:${color};border:1px solid ${color}">${esc(data.threat_level)}</span>
          <div class="meta">${data.indicators.length} indicator(s) found · scanned ${esc(data.scanned_at.slice(0,19).replace('T',' '))} UTC</div>
        </div>
      </div>

      <dl class="email-summary">
        <dt>Subject</dt><dd>${esc(data.email.subject)}</dd>
        <dt>From</dt><dd>${esc(data.email.sender)}</dd>
        <dt>Reply-To</dt><dd>${esc(data.email.reply_to)}</dd>
        <dt>Date</dt><dd>${esc(data.email.date)}</dd>
        <dt>URLs</dt><dd>${data.email.url_count}</dd>
        <dt>Attachments</dt><dd>${data.email.attachment_count}</dd>
      </dl>
    </div>

    <div class="panel">
      <div class="panel-title">Indicators</div>
      ${indHtml}
    </div>`;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}
</script>
</body>
</html>"""


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print("\n" + "─" * 50)
    print("  Email Threat Analyzer — Web Interface")
    print(f"  Open → http://localhost:{port}")
    print("─" * 50 + "\n")
    app.run(host=host, port=port, debug=False, threaded=True)
