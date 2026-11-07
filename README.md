# 🔍 Email Threat Analyzer

> **🚀 [Live Demo →](https://email-threat-analyzer-zt7f.onrender.com)** &nbsp;·&nbsp; Paste a phishing email (or pick a bundled sample) and see it analyzed in your browser.
> *Hosted on Render free tier — first load may take ~30 seconds while the container wakes.*

[![Live Demo](https://img.shields.io/badge/Live_Demo-Online-success?style=flat-square)](https://email-threat-analyzer-zt7f.onrender.com)
![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![Docker](https://img.shields.io/badge/Docker-ready-blue?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://github.com/AhmedDAH1/email-threat-analyzer/actions/workflows/ci.yml/badge.svg)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)

A modular phishing detection engine that performs multi-layer email security analysis similar to real-world SOC tooling. Parses raw `.eml` files, scores each email on a 0–100 threat scale, and optionally enriches findings with live threat intelligence via VirusTotal. Available as a CLI tool and a web interface.

---

## Why I Built This

Phishing remains one of the most common attack vectors in real-world environments. I wanted to understand — by building it — how security tools actually classify a suspicious email, rather than treating detection as a black box. This project combines header analysis, URL inspection, attachment inspection, content heuristics, and threat-intelligence enrichment into a single scored verdict, the same layered approach commercial email-security gateways use.

---

## Validation Against Real-World Phishing

The analyzer was tested against the **Nazario phishing corpus**, a widely-used research dataset of real phishing emails collected in the wild.

| Metric | Result |
|---|---|
| Emails analyzed | 414 |
| Flagged (LOW or higher) | 306 (**73%**) |
| Scored CLEAN | 99 |

The 73% flag rate reflects honest detection trade-offs. The corpus dates from the mid-2000s, and a meaningful share of the CLEAN results are plain-text scams with no URLs, attachments, or spoofed headers — they carry little *structural* signal for a heuristic analyzer to catch, even though a human reader would recognize the social-engineering intent. This is the well-known gap between structural detection (what this tool does) and semantic/NLP-based detection (a natural next step). Reporting the real number rather than claiming 100% reflects how detection engineering actually works: every detector has a measurable true-positive rate and a known blind spot.

> The corpus itself is not redistributed in this repo. It can be obtained from public phishing-research archives.

---

## Demo

```bash
python3 main.py samples/phishing_test.eml
```

```
============================================================
  EMAIL THREAT ANALYZER — SCAN REPORT
============================================================

EMAIL SUMMARY
  Subject   : Urgent: Your account has been suspended
  From      : "PayPal Security" <security@paypa1-verify.com>
  Reply-To  : phisher@evil-domain.ru
  Date      : Mon, 10 Apr 2026 08:23:11 +0000

THREAT ASSESSMENT
  Score : 100/100
  Level : CRITICAL

INDICATORS (7 found)

  [1] display_name_spoofing [severity 7] (header)
      Display name contains 'paypal' but sending domain is 'paypa1-verify.com'

  [2] reply_to_mismatch [severity 6] (header)
      From domain 'paypa1-verify.com' doesn't match Reply-To domain 'evil-domain.ru'

  [3] misleading_subdomain [severity 8] (url)
      Brand 'paypal' appears in subdomain but not in root domain 'evil.com'

  [4] url_shortener [severity 5] (url)
      URL uses a shortener service that hides the real destination

  [5] dangerous_extension [severity 8] (attachment)
      Attachment has a potentially executable extension '.exe'

  [6] double_extension [severity 9] (attachment)
      Attachment uses double extension to disguise executable: 'invoice.pdf.exe'

  [7] urgency_language [severity 4] (content)
      Email uses urgency or fear tactics to pressure the recipient
============================================================
```

---

## Web Interface

A Flask web app provides a browser-based version of the analyzer — try the [live demo](https://email-threat-analyzer-zt7f.onrender.com) or run it locally.

- Pick a bundled sample or paste raw `.eml` content
- See the threat score, level, email summary, and full indicator breakdown rendered live
- Emails are analyzed **in memory** — nothing is written to disk
- Path-traversal-guarded sample loading and a 1 MB cap on pasted input

```bash
# Run the web interface locally with Docker (recommended)
docker compose up        # then open http://localhost:8000

# Or run directly
python3 web_app.py       # then open http://localhost:8000
```

---

## Features

| Module | What It Detects | Severity Range |
|---|---|---|
| Header analysis | Sender spoofing, display name tricks, reply-to mismatch | 6–8 |
| URL analysis | Misleading subdomains, URL shorteners, IP-based URLs, lookalike domains | 5–8 |
| Attachment analysis | Dangerous extensions, double-extension spoofing, content-type mismatch | 4–9 |
| Content analysis | Urgency language, credential-harvesting requests, HTML link mismatch | 4–9 |
| VirusTotal integration | URL and file-hash lookups against 70+ AV engines (optional) | 4–10 |
| Threat scoring | Anchored 0–100 score weighted by indicator confidence | — |
| Reporters | Colored terminal output or JSON report | — |

---

## Threat Scoring

Each indicator carries a severity from 1–10, scaled by a **category weight** reflecting how reliable each signal is:

| Category | Weight | Rationale |
|---|---|---|
| Attachment | 1.4× | Hardest to fake, highest risk |
| Header | 1.2× | Strong technical signal |
| URL | 1.1× | Reliable but context-dependent |
| Content | 0.8× | Can appear in legitimate emails |

The score **anchors on the single strongest indicator** (so one high-confidence signal flags appropriately on its own), then adds remaining indicators at geometrically decreasing weight (so corroborating signals raise confidence without weak indicators diluting strong ones). Final score is capped at 100 and mapped to a threat level:

| Score | Level |
|---|---|
| 0–19 | CLEAN |
| 20–39 | LOW |
| 40–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

The sample set includes a **legitimate control email** (`samples/real/legitimate_1.eml`) that correctly scores CLEAN — demonstrating low false-positive behavior, not just true-positive detection.

---

## VirusTotal Integration

Pass your API key via `--virustotal` to enrich the analysis with live threat intelligence:

- **URL lookups** — each URL is checked against 70+ antivirus engines
- **File-hash lookups** — attachments are hashed (SHA256) and checked against VT's database
- **Opt-in only** — the tool works fully without a key; VT is never required

Get a free API key at https://virustotal.com — 4 lookups/minute on the free tier.

> Never hardcode your API key. Pass it via the CLI flag or an environment variable. (VirusTotal is disabled in the hosted web demo.)

---

## Installation

### Option 1 — Docker (recommended)

```bash
git clone https://github.com/AhmedDAH1/email-threat-analyzer.git
cd email-threat-analyzer
docker compose up
# Open http://localhost:8000
```

### Option 2 — Local Python

```bash
git clone https://github.com/AhmedDAH1/email-threat-analyzer.git
cd email-threat-analyzer
pip install -r requirements.txt

# CLI
python3 main.py samples/phishing_test.eml

# Web interface
python3 web_app.py
```

---

## CLI Usage

```bash
# Terminal report (default)
python3 main.py samples/phishing_test.eml

# JSON output
python3 main.py samples/phishing_test.eml --format json

# Save JSON report to file
python3 main.py samples/phishing_test.eml --format json --output report.json

# With VirusTotal integration
python3 main.py samples/phishing_test.eml --virustotal YOUR_API_KEY

# Send MEDIUM-or-worse verdicts to SOAR-Lite as incidents
SOAR_WEBHOOK_SECRET=... python3 main.py samples/phishing_test.eml --forward http://localhost:8000
```

### CLI Options

```
positional arguments:
  eml_file              Path to the .eml file to analyze

options:
  --format              Output format: terminal | json (default: terminal)
  --output FILE         Save JSON report to a file (use with --format json)
  --virustotal API_KEY  Enable VirusTotal URL and file-hash lookups
  --forward URL         Send the verdict to SOAR-Lite (needs SOAR_WEBHOOK_SECRET)
  --forward-min LEVEL   Only forward verdicts at or above LEVEL (default: MEDIUM)
```

### Sending verdicts to SOAR-Lite

A phishing verdict can become an incident in
[SOAR-Lite](https://github.com/AhmedDAH1/soar-lite), where the URLs and
attachment hashes are extracted as IOCs and enriched, playbooks escalate it
and an analyst works the case:

```bash
# SOAR-Lite running with WEBHOOK_SECRET set; use the same value here
export SOAR_WEBHOOK_SECRET=<SOAR-Lite's WEBHOOK_SECRET>
python3 main.py suspicious.eml --forward http://localhost:8000
```

The verdict goes to SOAR-Lite's email gateway webhook, signed with HMAC-SHA256
over a timestamp and the body, which SOAR-Lite verifies before creating the
incident. Verdicts below `--forward-min` stay local. The subject line and
sender are attacker-written, which is why SOAR-Lite escapes everything it
displays.

---

## Project Structure

```
email-threat-analyzer/
├── main.py                         # CLI entry point
├── web_app.py                      # Flask web interface
├── Dockerfile                      # Production container (gunicorn, non-root)
├── docker-compose.yml              # One-command launch
├── Makefile                        # Shortcuts for common commands
├── analyzer/
│   ├── engine.py                   # Shared analysis pipeline (CLI + web)
│   ├── analyzers/                  # One module per analysis domain
│   │   ├── header_analyzer.py      # Spoofing, reply-to mismatch
│   │   ├── url_analyzer.py         # Suspicious URLs, shorteners, subdomains
│   │   ├── attachment_analyzer.py  # Dangerous extensions, content-type mismatch
│   │   └── content_analyzer.py     # Urgency language, credential harvesting
│   ├── core/                       # Shared infrastructure
│   │   ├── models.py               # EmailMessage, ThreatIndicator, ScanResult
│   │   ├── parser.py               # .eml → EmailMessage
│   │   ├── scorer.py               # Weighted threat scoring engine
│   │   └── virustotal.py           # VirusTotal API client
│   └── reporters/                  # Output formatters
│       ├── terminal_reporter.py    # Colored CLI output
│       ├── json_reporter.py        # Machine-readable JSON
│       └── soar_forwarder.py       # Signed webhooks to SOAR-Lite
├── tests/                          # 48 unit tests across all modules
└── samples/                        # Sample .eml files (4 phishing + 1 legitimate control)
```

---

## Test Suite

48 tests across all modules — all passing:

```
tests/test_attachment_analyzer.py    5 tests
tests/test_content_analyzer.py       8 tests
tests/test_parser.py                10 tests
tests/test_scorer.py                 6 tests
tests/test_soar_forwarder.py        14 tests
tests/test_url_analyzer.py           5 tests
```

```bash
make test    # or: pytest tests/
```

---

## Skills Demonstrated

| Skill | Where in this project |
|---|---|
| Email protocol parsing (RFC 5322) | `analyzer/core/parser.py` |
| Threat detection heuristics | `analyzer/analyzers/` — header, URL, attachment, content |
| Security scoring system | `analyzer/core/scorer.py` — anchored, confidence-weighted |
| Real-world validation | Tested against the Nazario phishing corpus (414 emails) |
| Modular architecture | Parsers, analyzers, scorer, reporters fully decoupled |
| REST API integration | VirusTotal API v3 with graceful degradation |
| Web development | Flask app, in-memory analysis, security-guarded endpoints |
| Containerization | Docker + gunicorn, non-root user |
| Cloud deployment | Live on Render |
| Integration | Signed webhooks to SOAR-Lite (`--forward`) |
| Unit testing | 48 pytest tests |
| CI/CD | GitHub Actions on every push |

---

## Tech Stack

- **Language**: Python 3.11+
- **Email parsing**: Python standard library `email` module
- **Web**: Flask, served by gunicorn in production
- **Threat intelligence**: VirusTotal API v3
- **Containerization**: Docker + docker-compose
- **Deployment**: Render
- **Architecture**: Modular — parsers, analyzers, scorer, and reporters fully decoupled
- **CI**: GitHub Actions — 48 tests run automatically on every push

---

## Author

**Ahmed Dahdouh** — Software Engineering Student · Cybersecurity Enthusiast

[![GitHub](https://img.shields.io/badge/GitHub-AhmedDAH1-black?style=flat-square&logo=github)](https://github.com/AhmedDAH1)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ahmed_Dahdouh-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/ahmed-dahdouh)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-AhmedDAH1-212C42?style=flat-square&logo=tryhackme)](https://tryhackme.com/p/AhmedDAH1)

---

## Related Projects

- [log_threat_detector](https://github.com/AhmedDAH1/log_threat_detector) — SIEM-style log analysis tool with Flask dashboard, WebSockets, and AbuseIPDB integration
- [network-scanner](https://github.com/AhmedDAH1/network-scanner) — Scapy-based network scanner with CVE lookup and web dashboard
- [soar-lite](https://github.com/AhmedDAH1/soar-lite) — incident-response automation platform with playbook engine and case management
- [attack-surface-mapper](https://github.com/AhmedDAH1/attack-surface-mapper) — attack-surface discovery with MITRE ATT&CK mapping and compliance checks

---

## License

MIT — see [LICENSE](LICENSE)
