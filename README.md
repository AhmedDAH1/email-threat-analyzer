# 🔍 Email Threat Analyzer

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://github.com/AhmedDAH1/email-threat-analyzer/actions/workflows/ci.yml/badge.svg)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)

A Python-based phishing detection tool that parses raw `.eml` files and runs multi-layer analysis across headers, URLs, attachments, and email body content — scoring each email on a 0–100 threat scale with detailed indicator reporting. Optionally enriched with live threat intelligence via VirusTotal.

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
  Score : 56/100
  Level : MEDIUM

INDICATORS (7 found)

  [1] display_name_spoofing [severity 7] (header)
      Display name contains 'paypal' but sending domain is 'paypa1-verify.com'
      Evidence: "PayPal Security" <security@paypa1-verify.com>

  [2] reply_to_mismatch [severity 6] (header)
      From domain 'paypa1-verify.com' doesn't match Reply-To domain 'evil-domain.ru'

  [3] misleading_subdomain [severity 8] (url)
      Brand 'paypal' appears in subdomain but not in root domain 'evil.com'
      Evidence: http://paypal-secure-login.evil.com/verify?token=abc123

  [4] url_shortener [severity 5] (url)
      URL uses a shortener service that hides the real destination
      Evidence: http://bit.ly/3xR9mNp

  [5] dangerous_extension [severity 8] (attachment)
      Attachment has a potentially executable extension '.exe'
      Evidence: invoice.pdf.exe

  [6] double_extension [severity 9] (attachment)
      Attachment uses double extension to disguise executable: 'invoice.pdf.exe'

  [7] urgency_language [severity 4] (content)
      Email uses urgency or fear tactics to pressure the recipient
      Evidence: within 24 hours

============================================================
```

---

## Features

| Module | What It Detects | Severity Range |
|---|---|---|
| Header analysis | Sender spoofing, display name tricks, reply-to mismatch | 6–8 |
| URL analysis | Misleading subdomains, URL shorteners, IP-based URLs, lookalike domains | 5–8 |
| Attachment analysis | Dangerous extensions, double extension spoofing, content-type mismatch, suspicious archives | 4–9 |
| Content analysis | Urgency language, credential harvesting requests, HTML link mismatch | 4–9 |
| VirusTotal integration | URL and file hash lookups against 70+ AV engines (optional) | 4–10 |
| Threat scoring | Weighted 0–100 score with category multipliers | — |
| Reporters | Colored terminal output or JSON report | — |

---

## Threat Scoring

Each indicator carries a severity from 1–10. The scorer applies **category weights** to reflect how reliable each signal is:

| Category | Weight | Rationale |
|---|---|---|
| Attachment | 1.4× | Hardest to fake, highest risk |
| Header | 1.2× | Strong technical signal |
| URL | 1.1× | Reliable but context-dependent |
| Content | 0.8× | Can appear in legitimate emails |

Final score is capped at 100 and mapped to a threat level:

| Score | Level |
|---|---|
| 0–19 | CLEAN |
| 20–39 | LOW |
| 40–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

---

## VirusTotal Integration

Pass your API key via `--virustotal` to enrich the analysis with live threat intelligence:

- **URL lookups** — each URL is checked against 70+ antivirus engines
- **File hash lookups** — attachments are hashed (SHA256) and checked against VT's database
- **Opt-in only** — the tool works fully without a key; VT is never required

Get a free API key at https://virustotal.com — 4 lookups/minute on the free tier.

> Never hardcode your API key in the source. Always pass it via the CLI flag or an environment variable.

---

## Project Structure

```
email-threat-analyzer/
├── main.py                         # CLI entry point
├── Makefile                        # Shortcuts for common commands
├── analyzer/
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
│       └── json_reporter.py        # Machine-readable JSON
├── tests/                          # 34 unit tests across all modules
└── samples/                        # Sample .eml files for testing
```

---

## Installation

```bash
git clone https://github.com/AhmedDAH1/email-threat-analyzer.git
cd email-threat-analyzer
pip install -r requirements.txt
```

---

## Usage

```bash
# Terminal report (default)
python3 main.py samples/phishing_test.eml

# JSON output
python3 main.py samples/phishing_test.eml --format json

# Save JSON report to file
python3 main.py samples/phishing_test.eml --format json --output report.json

# With VirusTotal integration
python3 main.py samples/phishing_test.eml --virustotal YOUR_API_KEY
```

---

## CLI Options

```
positional arguments:
  eml_file              Path to the .eml file to analyze

options:
  --format              Output format: terminal | json (default: terminal)
  --output FILE         Save JSON report to a file (use with --format json)
  --virustotal API_KEY  Enable VirusTotal URL and file hash lookups
```

---

## Makefile

```bash
make install    # Install dependencies
make test       # Run all 34 unit tests
make run        # Run tool on sample phishing email
make run-json   # Run tool with JSON output
make clean      # Remove __pycache__ files
```

---

## Test Suite

34 tests across 4 modules — all passing:

```
tests/test_attachment_analyzer.py    5 tests
tests/test_content_analyzer.py       8 tests
tests/test_parser.py                10 tests
tests/test_scorer.py                 6 tests
tests/test_url_analyzer.py           4 tests (+ 1 integration)
```

---

## Tech Stack

- **Language**: Python 3.11+
- **Email parsing**: Python standard library `email` module
- **Threat intelligence**: VirusTotal API v3
- **HTTP client**: `requests`
- **Architecture**: Modular — parsers, analyzers, scorer, and reporters fully decoupled
- **CI**: GitHub Actions — 34 tests run automatically on every push

---

## Author

**Ahmed Dahdouh**
Software Engineering Student · Cybersecurity Enthusiast

[![GitHub](https://img.shields.io/badge/GitHub-AhmedDAH1-black?style=flat-square&logo=github)](https://github.com/AhmedDAH1)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ahmed_Dahdouh-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/ahmed-dahdouh)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-AhmedDAH1-212C42?style=flat-square&logo=tryhackme)](https://tryhackme.com/p/AhmedDAH1)

---

## Related Projects

- [log_threat_detector](https://github.com/AhmedDAH1/log_threat_detector) — SIEM-style log analysis tool with Flask dashboard, WebSockets, and AbuseIPDB integration
- [network-scanner](https://github.com/AhmedDAH1/network-scanner) — Scapy-based network scanner with CVE lookup and web dashboard

---

## License

MIT — see [LICENSE](LICENSE)