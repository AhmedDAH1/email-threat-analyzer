# email-threat-analyzer

A Python-based phishing detection tool that parses raw `.eml` files, analyzes headers, URLs, attachments, and email body content for phishing indicators, scores threat level, and generates reports.

![CI](https://github.com/AhmedDAH1/email-threat-analyzer/actions/workflows/ci.yml/badge.svg)

---

## Features

- **Header analysis** — detects sender spoofing, display name tricks, reply-to mismatch
- **URL analysis** — flags misleading subdomains, URL shorteners, IP-based URLs
- **Attachment analysis** — catches dangerous extensions, double extension spoofing, content-type mismatch
- **Content analysis** — detects urgency language, credential harvesting, HTML link mismatch
- **Threat scoring** — weighted 0–100 score with CLEAN / LOW / MEDIUM / HIGH / CRITICAL levels
- **Multiple output formats** — colored terminal report or JSON

---

## Project Structure

```
email-threat-analyzer/
├── analyzer/
│   ├── analyzers/          # One module per analysis domain
│   │   ├── header_analyzer.py
│   │   ├── url_analyzer.py
│   │   ├── attachment_analyzer.py
│   │   └── content_analyzer.py
│   ├── core/               # Shared infrastructure
│   │   ├── models.py
│   │   ├── parser.py
│   │   └── scorer.py
│   └── reporters/          # Output formatters
│       ├── terminal_reporter.py
│       └── json_reporter.py
├── tests/                  # 34 unit tests
├── samples/                # Sample .eml files
└── main.py                 # CLI entrypoint
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
```

---

## Makefile Commands

```bash
make install   # Install dependencies
make test      # Run all tests
make run       # Run tool on sample phishing email
make run-json  # Run tool with JSON output
make clean     # Remove __pycache__ files
```

---

## Test Suite

```
34 tests across 4 modules — all passing
```

---

## Related Projects

- [log_threat_detector](https://github.com/AhmedDAH1/log_threat_detector) — SIEM-style log analysis tool with Flask dashboard, WebSockets, and AbuseIPDB integration
- [network-scanner](https://github.com/AhmedDAH1/network-scanner) — Scapy-based network scanner with CVE lookup and web dashboard